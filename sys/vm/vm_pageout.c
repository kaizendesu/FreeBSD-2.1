/*
 * Copyright (c) 1991 Regents of the University of California.
 * All rights reserved.
 * Copyright (c) 1994 John S. Dyson
 * All rights reserved.
 * Copyright (c) 1994 David Greenman
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * The Mach Operating System project at Carnegie-Mellon University.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)vm_pageout.c	7.4 (Berkeley) 5/7/91
 *
 *
 * Copyright (c) 1987, 1990 Carnegie-Mellon University.
 * All rights reserved.
 *
 * Authors: Avadis Tevanian, Jr., Michael Wayne Young
 *
 * Permission to use, copy, modify and distribute this software and
 * its documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND
 * FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 *
 * $FreeBSD$
 */

/*
 *	The proverbial page-out daemon.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/signalvar.h>
#include <sys/vnode.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_kern.h>
#include <vm/swap_pager.h>
#include <vm/vnode_pager.h>

int vm_pages_needed;		/* Event on which pageout daemon sleeps */

int vm_pageout_pages_needed;	/* flag saying that the pageout daemon needs pages */

extern int npendingio;
int vm_pageout_req_swapout;	/* XXX */
int vm_daemon_needed;
extern int nswiodone;
extern int swap_pager_full;
extern int vm_swap_size;
extern int vfs_update_wakeup;

#define MAXSCAN 1024		/* maximum number of pages to scan in queues */

#define MAXLAUNDER (cnt.v_page_count > 1800 ? 32 : 16)

#define VM_PAGEOUT_PAGE_COUNT 8
int vm_pageout_page_count = VM_PAGEOUT_PAGE_COUNT;

int vm_page_max_wired;		/* XXX max # of wired pages system-wide */

static void vm_req_vmdaemon __P((void));

/*
 * vm_pageout_clean:
 * 	cleans a vm_page
 */
int
vm_pageout_clean(m, sync)
	register vm_page_t m;
	int sync;
{
	/*
	 * Clean the page and remove it from the laundry.
	 *
	 * We set the busy bit to cause potential page faults on this page to
	 * block.
	 *
	 * And we set pageout-in-progress to keep the object from disappearing
	 * during pageout.  This guarantees that the page won't move from the
	 * inactive queue.  (However, any other page on the inactive queue may
	 * move!)
	 */

	register vm_object_t object;
	register vm_pager_t pager;
	int pageout_status[VM_PAGEOUT_PAGE_COUNT];
	vm_page_t ms[VM_PAGEOUT_PAGE_COUNT], mb[VM_PAGEOUT_PAGE_COUNT];
	int pageout_count, b_pageout_count;
	int anyok = 0;
	int i;
	vm_offset_t offset = m->offset;

	object = m->object;
	if (!object) {
		printf("pager: object missing\n");
		return 0;
	}
	if (!object->pager && (object->flags & OBJ_INTERNAL) == 0) {
		printf("pager: non internal obj without pager\n");
	}
	/*
	 * Try to collapse the object before making a pager for it.  We must
	 * unlock the page queues first. We try to defer the creation of a
	 * pager until all shadows are not paging.  This allows
	 * vm_object_collapse to work better and helps control swap space
	 * size. (J. Dyson 11 Nov 93)
	 */

	if (!object->pager &&
	    (cnt.v_free_count + cnt.v_cache_count) < cnt.v_pageout_free_min)
		return 0;

	if ((!sync && m->hold_count != 0) || m->wire_count ||
	    ((m->busy != 0) || (m->flags & PG_BUSY)))
		return 0;

	if (!sync && object->shadow) {
		vm_object_collapse(object);
	}
	pageout_count = 1;
	ms[0] = m;

	pager = object->pager;
	if (pager) {
		for (i = 1; i < vm_pageout_page_count; i++) {
			vm_page_t mt;

			ms[i] = mt = vm_page_lookup(object, offset + i * NBPG);
			if (mt) {
				if (mt->flags & (PG_BUSY|PG_CACHE) || mt->busy)
					break;
				/*
				 * we can cluster ONLY if: ->> the page is NOT
				 * busy, and is NOT clean the page is not
				 * wired, busy, held, or mapped into a buffer.
				 * and one of the following: 1) The page is
				 * inactive, or a seldom used active page. 2)
				 * or we force the issue.
				 */
				vm_page_test_dirty(mt);
				if ((mt->dirty & mt->valid) != 0
				    && ((mt->flags & PG_INACTIVE) ||
						(sync == VM_PAGEOUT_FORCE))
				    && (mt->wire_count == 0)
				    && (mt->hold_count == 0))
					pageout_count++;
				else
					break;
			} else
				break;
		}

		if ((pageout_count < vm_pageout_page_count) && (offset != 0)) {
			b_pageout_count = 0;
			for (i = 0; i < vm_pageout_page_count-pageout_count; i++) {
				vm_page_t mt;

				mt = vm_page_lookup(object, offset - (i + 1) * NBPG);
				if (mt) {
					if (mt->flags & (PG_BUSY|PG_CACHE) || mt->busy)
						break;
					vm_page_test_dirty(mt);
					if ((mt->dirty & mt->valid) != 0
					    && ((mt->flags & PG_INACTIVE) ||
							(sync == VM_PAGEOUT_FORCE))
					    && (mt->wire_count == 0)
					    && (mt->hold_count == 0)) {
						mb[b_pageout_count] = mt;
						b_pageout_count++;
						if ((offset - (i + 1) * NBPG) == 0)
							break;
					} else
						break;
				} else
					break;
			}
			if (b_pageout_count > 0) {
				for(i=pageout_count - 1;i>=0;--i) {
					ms[i+b_pageout_count] = ms[i];
				}
				for(i=0;i<b_pageout_count;i++) {
					ms[i] = mb[b_pageout_count - (i + 1)];
				}
				pageout_count += b_pageout_count;
			}
		}

		/*
		 * we allow reads during pageouts...
		 */
		for (i = 0; i < pageout_count; i++) {
			ms[i]->flags |= PG_BUSY;
			vm_page_protect(ms[i], VM_PROT_NONE);
		}
		object->paging_in_progress += pageout_count;
	} else {

		m->flags |= PG_BUSY;

		vm_page_protect(m, VM_PROT_NONE);

		object->paging_in_progress++;

		pager = vm_pager_allocate(PG_DFLT, 0,
		    object->size, VM_PROT_ALL, 0);
		if (pager != NULL) {
			object->pager = pager;
		}
	}

	/*
	 * If there is no pager for the page, use the default pager.  If
	 * there's no place to put the page at the moment, leave it in the
	 * laundry and hope that there will be paging space later.
	 */

	if ((pager && pager->pg_type == PG_SWAP) ||
	    (cnt.v_free_count + cnt.v_cache_count) >= cnt.v_pageout_free_min) {
		if (pageout_count == 1) {
			pageout_status[0] = pager ?
			    vm_pager_put(pager, m,
			    ((sync || (object == kernel_object)) ? TRUE : FALSE)) :
			    VM_PAGER_FAIL;
		} else {
			if (!pager) {
				for (i = 0; i < pageout_count; i++)
					pageout_status[i] = VM_PAGER_FAIL;
			} else {
				vm_pager_put_pages(pager, ms, pageout_count,
				    ((sync || (object == kernel_object)) ? TRUE : FALSE),
				    pageout_status);
			}
		}
	} else {
		for (i = 0; i < pageout_count; i++)
			pageout_status[i] = VM_PAGER_FAIL;
	}

	for (i = 0; i < pageout_count; i++) {
		switch (pageout_status[i]) {
		case VM_PAGER_OK:
			++anyok;
			break;
		case VM_PAGER_PEND:
			++anyok;
			break;
		case VM_PAGER_BAD:
			/*
			 * Page outside of range of object. Right now we
			 * essentially lose the changes by pretending it
			 * worked.
			 */
			pmap_clear_modify(VM_PAGE_TO_PHYS(ms[i]));
			ms[i]->dirty = 0;
			break;
		case VM_PAGER_ERROR:
		case VM_PAGER_FAIL:
			/*
			 * If page couldn't be paged out, then reactivate the
			 * page so it doesn't clog the inactive list.  (We
			 * will try paging out it again later).
			 */
			if (ms[i]->flags & PG_INACTIVE)
				vm_page_activate(ms[i]);
			break;
		case VM_PAGER_AGAIN:
			break;
		}


		/*
		 * If the operation is still going, leave the page busy to
		 * block all other accesses. Also, leave the paging in
		 * progress indicator set so that we don't attempt an object
		 * collapse.
		 */
		if (pageout_status[i] != VM_PAGER_PEND) {
			vm_object_pip_wakeup(object);
			if ((ms[i]->flags & (PG_REFERENCED|PG_WANTED)) ||
			    pmap_is_referenced(VM_PAGE_TO_PHYS(ms[i]))) {
				pmap_clear_reference(VM_PAGE_TO_PHYS(ms[i]));
				ms[i]->flags &= ~PG_REFERENCED;
				if (ms[i]->flags & PG_INACTIVE)
					vm_page_activate(ms[i]);
			}
			PAGE_WAKEUP(ms[i]);
		}
	}
	return anyok;
}

#ifndef NO_SWAPPING
/*
 *	vm_pageout_object_deactivate_pages
 *
 *	Deactivate pages in the object chain until desired count
 *	is reached.
 *
 *	The object and map must be locked.
 */
static void
vm_pageout_object_deactivate_pages(map, object, desired, map_remove_only)
	vm_map_t map;
	vm_object_t object;
	u_int desired;
	int map_remove_only;
{
	register vm_page_t p, next;
	int rcount;
	int s;

	if (object->pager && (object->pager->pg_type == PG_DEVICE))
		return;

	while (object) {
		if (vm_map_pmap(map)->pm_stats.resident_count <= desired)
			return;
		if (object->paging_in_progress)
			return;

		/*
		 * scan the objects entire memory queue
		 */
		rcount = object->resident_page_count;
		p = object->memq.tqh_first;
		while (p && (rcount-- > 0)) {
			if (vm_map_pmap(map)->pm_stats.resident_count <= desired)
				return;
			next = p->listq.tqe_next;
			cnt.v_pdpages++;
			if (p->wire_count != 0 ||
			    p->hold_count != 0 ||
			    p->busy != 0 ||
			    (p->flags & PG_BUSY) ||
			    !pmap_page_exists(vm_map_pmap(map), VM_PAGE_TO_PHYS(p))) {
				p = next;
				continue;
			}

			if (pmap_is_referenced(VM_PAGE_TO_PHYS(p))) {
				pmap_clear_reference(VM_PAGE_TO_PHYS(p));
				p->flags |= PG_REFERENCED;
			}

			if ((p->flags & PG_INACTIVE) &&
				(p->flags & PG_REFERENCED)) {
				vm_page_activate(p);
			}

			/*
			 * if a page is active, not wired and is in the processes
			 * pmap, then deactivate the page.
			 */
			if (p->flags & PG_ACTIVE) {
				if ((p->flags & PG_REFERENCED) == 0) {
					p->act_count -= min(p->act_count, ACT_DECLINE);
					vm_page_protect(p, VM_PROT_NONE);
					if (!map_remove_only)
						vm_page_deactivate(p);
				} else {
					p->flags &= ~PG_REFERENCED;
					s = splbio();
					TAILQ_REMOVE(&vm_page_queue_active, p, pageq);
					TAILQ_INSERT_TAIL(&vm_page_queue_active, p, pageq);
					splx(s);
				}
			} else if (p->flags & PG_INACTIVE) {
				vm_page_protect(p, VM_PROT_NONE);
			}
			p = next;
		}
		object = object->shadow;
	}
	return;
}

/*
 * deactivate some number of pages in a map, try to do it fairly, but
 * that is really hard to do.
 */
static void
vm_pageout_map_deactivate_pages(map, desired)
	vm_map_t map;
	u_int desired;
{
	vm_map_entry_t tmpe;
	vm_object_t obj, bigobj;

	vm_map_reference(map);
	if (!lock_try_write(&map->lock)) {
		vm_map_deallocate(map);
		return;
	}

	bigobj = NULL;

	/*
	 * first, search out the biggest object, and try to free pages from
	 * that.
	 */
	tmpe = map->header.next;
	while (tmpe != &map->header) {
		if ((tmpe->is_sub_map == 0) && (tmpe->is_a_map == 0)) {
			obj = tmpe->object.vm_object;
			if ((obj != NULL) && ((bigobj == NULL) ||
				 (bigobj->resident_page_count < obj->resident_page_count))) {
				bigobj = obj;
			}
		}
		tmpe = tmpe->next;
	}

	if (bigobj)
		vm_pageout_object_deactivate_pages(map, bigobj, desired, 0);

	/*
	 * Next, hunt around for other pages to deactivate.  We actually
	 * do this search sort of wrong -- .text first is not the best idea.
	 */
	tmpe = map->header.next;
	while (tmpe != &map->header) {
		if (vm_map_pmap(map)->pm_stats.resident_count <= desired)
			break;
		if ((tmpe->is_sub_map == 0) && (tmpe->is_a_map == 0)) {
			obj = tmpe->object.vm_object;
			if (obj)
				vm_pageout_object_deactivate_pages(map, obj, desired, 0);
		}
		tmpe = tmpe->next;
	};

	/*
	 * Remove all mappings if a process is swapped out, this will free page
	 * table pages.
	 */
	if (desired == 0)
		pmap_remove(vm_map_pmap(map),
			VM_MIN_ADDRESS, VM_MAXUSER_ADDRESS);
	vm_map_unlock(map);
	vm_map_deallocate(map);
	return;
}
#endif

/*
 *	vm_pageout_scan does the dirty work for the pageout daemon.
 */
int
vm_pageout_scan()
{
	vm_page_t m;
	int page_shortage, maxscan, maxlaunder, pcount;
	int pages_freed;
	vm_page_t next;
	struct proc *p, *bigproc;
	vm_offset_t size, bigsize;
	vm_object_t object;
	int force_wakeup = 0;
	int vnodes_skipped = 0;
	int s;

	pages_freed = 0;

	/*
	 * Start scanning the inactive queue for pages we can free. We keep
	 * scanning until we have enough free pages or we have scanned through
	 * the entire queue.  If we encounter dirty pages, we start cleaning
	 * them.
	 */

rescan0:
	maxlaunder = (cnt.v_inactive_target > MAXLAUNDER) ?
	    MAXLAUNDER : cnt.v_inactive_target;

rescan1:
	maxscan = cnt.v_inactive_count;
	m = vm_page_queue_inactive.tqh_first;
	while ((m != NULL) && (maxscan-- > 0) &&
	    ((cnt.v_cache_count + cnt.v_free_count) < (cnt.v_cache_min + cnt.v_free_target))) {
		vm_page_t next;

		cnt.v_pdpages++;
		next = m->pageq.tqe_next;

		if ((m->flags & PG_INACTIVE) == 0) {
			goto rescan1;
		}

		/*
		 * dont mess with busy pages
		 */
		if (m->hold_count || m->busy || (m->flags & PG_BUSY)) {
			s = splbio();
			TAILQ_REMOVE(&vm_page_queue_inactive, m, pageq);
			TAILQ_INSERT_TAIL(&vm_page_queue_inactive, m, pageq);
			splx(s);
			m = next;
			continue;
		}
		if (((m->flags & PG_REFERENCED) == 0) &&
		    pmap_is_referenced(VM_PAGE_TO_PHYS(m))) {
			m->flags |= PG_REFERENCED;
		}
		if (m->object->ref_count == 0) {
			m->flags &= ~PG_REFERENCED;
			pmap_clear_reference(VM_PAGE_TO_PHYS(m));
		}
		if ((m->flags & (PG_REFERENCED|PG_WANTED)) != 0) {
			m->flags &= ~PG_REFERENCED;
			pmap_clear_reference(VM_PAGE_TO_PHYS(m));
			vm_page_activate(m);
			if (m->act_count < ACT_MAX)
				m->act_count += ACT_ADVANCE;
			m = next;
			continue;
		}

		vm_page_test_dirty(m);
		if (m->dirty == 0) {
			if (m->bmapped == 0) {
				if (m->valid == 0) {
					pmap_page_protect(VM_PAGE_TO_PHYS(m), VM_PROT_NONE);
					vm_page_free(m);
					cnt.v_dfree++;
				} else {
					vm_page_cache(m);
				}
				++pages_freed;
			}
		} else if (maxlaunder > 0) {
			int written;
			struct vnode *vp = NULL;

			object = m->object;
			if ((object->flags & OBJ_DEAD) || !vm_object_lock_try(object)) {
				m = next;
				continue;
			}

			if (object->pager && object->pager->pg_type == PG_VNODE) {
				vp = ((vn_pager_t) object->pager->pg_data)->vnp_vp;
				if (VOP_ISLOCKED(vp) || vget(vp, 1)) {
					vm_object_unlock(object);
					if (object->flags & OBJ_WRITEABLE)
						++vnodes_skipped;
					m = next;
					continue;
				}
				/*
				 * We might have blocked above, so make sure
				 * the page didn't move on us.
				 */
				if ((m->flags & PG_INACTIVE) == 0 || m->dirty == 0) {
					vput(vp);
					vm_object_unlock(object);
					if (object->flags & OBJ_WRITEABLE)
						++vnodes_skipped;
					m = next;
					continue;
				}
			}

			/*
			 * If a page is dirty, then it is either being washed
			 * (but not yet cleaned) or it is still in the
			 * laundry.  If it is still in the laundry, then we
			 * start the cleaning operation.
			 */
			written = vm_pageout_clean(m, 0);

			if (vp)
				vput(vp);

			vm_object_unlock(object);

			if (!next) {
				break;
			}
			maxlaunder -= written;
		}
		m = next;
	}

	/*
	 * Compute the page shortage.  If we are still very low on memory be
	 * sure that we will move a minimal amount of pages from active to
	 * inactive.
	 */

	page_shortage = cnt.v_inactive_target -
	    (cnt.v_free_count + cnt.v_inactive_count + cnt.v_cache_count);
	if (page_shortage <= 0) {
		if (pages_freed == 0) {
			page_shortage = cnt.v_free_min - cnt.v_free_count;
		} else {
			page_shortage = 1;
		}
	}
rescan_active:
	maxscan = MAXSCAN;
	pcount = cnt.v_active_count;
	m = vm_page_queue_active.tqh_first;
	while ((m != NULL) && (maxscan > 0) && (pcount-- > 0) && (page_shortage > 0)) {

		cnt.v_pdpages++;
		next = m->pageq.tqe_next;

		if ((m->flags & PG_ACTIVE) == 0)
			break;

		/*
		 * Don't deactivate pages that are busy.
		 */
		if ((m->busy != 0) ||
		    (m->flags & PG_BUSY) ||
		    (m->hold_count != 0)) {
			s = splbio();
			TAILQ_REMOVE(&vm_page_queue_active, m, pageq);
			TAILQ_INSERT_TAIL(&vm_page_queue_active, m, pageq);
			splx(s);
			m = next;
			continue;
		}
		if (m->object->ref_count && ((m->flags & (PG_REFERENCED|PG_WANTED)) ||
			pmap_is_referenced(VM_PAGE_TO_PHYS(m)))) {
			int s;

			pmap_clear_reference(VM_PAGE_TO_PHYS(m));
			m->flags &= ~PG_REFERENCED;
			if (m->act_count < ACT_MAX) {
				m->act_count += ACT_ADVANCE;
			}
			s = splbio();
			TAILQ_REMOVE(&vm_page_queue_active, m, pageq);
			TAILQ_INSERT_TAIL(&vm_page_queue_active, m, pageq);
			splx(s);
		} else {
			m->flags &= ~PG_REFERENCED;
			pmap_clear_reference(VM_PAGE_TO_PHYS(m));
			m->act_count -= min(m->act_count, ACT_DECLINE);

			/*
			 * if the page act_count is zero -- then we deactivate
			 */
			if (!m->act_count && (page_shortage > 0)) {
				vm_page_deactivate(m);
				--page_shortage;
			} else if (m->act_count) {
				s = splbio();
				TAILQ_REMOVE(&vm_page_queue_active, m, pageq);
				TAILQ_INSERT_TAIL(&vm_page_queue_active, m, pageq);
				splx(s);
			}
		}
		maxscan--;
		m = next;
	}

	/*
	 * We try to maintain some *really* free pages, this allows interrupt
	 * code to be guaranteed space.
	 */
	while (cnt.v_free_count < cnt.v_free_reserved) {
		m = vm_page_queue_cache.tqh_first;
		if (!m)
			break;
		vm_page_free(m);
		cnt.v_dfree++;
	}

	/*
	 * If we didn't get enough free pages, and we have skipped a vnode
	 * in a writeable object, wakeup the sync daemon.  And kick swapout
	 * if we did not get enough free pages.
	 */
	if ((cnt.v_cache_count + cnt.v_free_count) < cnt.v_free_target) {
		if (vnodes_skipped &&
		    (cnt.v_cache_count + cnt.v_free_count) < cnt.v_free_min) {
			if (!vfs_update_wakeup) {
				vfs_update_wakeup = 1;
				wakeup((caddr_t) &vfs_update_wakeup);
			}
		}
#ifndef NO_SWAPPING
		/*
		 * now swap processes out if we are in low memory conditions
		 */
		if (!swap_pager_full && vm_swap_size &&
			vm_pageout_req_swapout == 0) {
			vm_pageout_req_swapout = 1;
			vm_req_vmdaemon();
		}
#endif
	}

#ifndef NO_SWAPPING
	if ((cnt.v_inactive_count + cnt.v_free_count + cnt.v_cache_count) <
	    (cnt.v_inactive_target + cnt.v_free_min)) {
		vm_req_vmdaemon();
	}
#endif

	/*
	 * make sure that we have swap space -- if we are low on memory and
	 * swap -- then kill the biggest process.
	 */
	if ((vm_swap_size == 0 || swap_pager_full) &&
	    ((cnt.v_free_count + cnt.v_cache_count) < cnt.v_free_min)) {
		bigproc = NULL;
		bigsize = 0;
		for (p = (struct proc *) allproc; p != NULL; p = p->p_next) {
			/*
			 * if this is a system process, skip it
			 */
			if ((p->p_flag & P_SYSTEM) || (p->p_pid == 1) ||
			    ((p->p_pid < 48) && (vm_swap_size != 0))) {
				continue;
			}
			/*
			 * if the process is in a non-running type state,
			 * don't touch it.
			 */
			if (p->p_stat != SRUN && p->p_stat != SSLEEP) {
				continue;
			}
			/*
			 * get the process size
			 */
			size = p->p_vmspace->vm_pmap.pm_stats.resident_count;
			/*
			 * if the this process is bigger than the biggest one
			 * remember it.
			 */
			if (size > bigsize) {
				bigproc = p;
				bigsize = size;
			}
		}
		if (bigproc != NULL) {
			killproc(bigproc, "out of swap space");
			bigproc->p_estcpu = 0;
			bigproc->p_nice = PRIO_MIN;
			resetpriority(bigproc);
			wakeup((caddr_t) &cnt.v_free_count);
		}
	}
	return force_wakeup;
}

/*
 *	vm_pageout is the high level pageout daemon.
 */
void
vm_pageout()
{
	(void) spl0();

	/*
	 * Initialize some paging parameters.
	 */

	cnt.v_interrupt_free_min = 2;

	if (cnt.v_page_count > 1024)
		cnt.v_free_min = 4 + (cnt.v_page_count - 1024) / 200;
	else
		cnt.v_free_min = 4;
	/*
	 * free_reserved needs to include enough for the largest swap pager
	 * structures plus enough for any pv_entry structs when paging.
	 */
	cnt.v_pageout_free_min = 6 + cnt.v_page_count / 1024 +
				cnt.v_interrupt_free_min;
	cnt.v_free_reserved = cnt.v_pageout_free_min + 6;
	cnt.v_free_target = 3 * cnt.v_free_min + cnt.v_free_reserved;
	cnt.v_free_min += cnt.v_free_reserved;

	if (cnt.v_page_count > 1024) {
		cnt.v_cache_max = (cnt.v_free_count - 1024) / 2;
		cnt.v_cache_min = (cnt.v_free_count - 1024) / 8;
		cnt.v_inactive_target = 2*cnt.v_cache_min + 192;
	} else {
		cnt.v_cache_min = 0;
		cnt.v_cache_max = 0;
		cnt.v_inactive_target = cnt.v_free_count / 4;
	}

	/* XXX does not really belong here */
	if (vm_page_max_wired == 0)
		vm_page_max_wired = cnt.v_free_count / 3;


	(void) swap_pager_alloc(0, 0, 0, 0);
	/*
	 * The pageout daemon is never done, so loop forever.
	 */
	while (TRUE) {
		int s = splhigh();

		if (!vm_pages_needed ||
			((cnt.v_free_count >= cnt.v_free_reserved) &&
			 (cnt.v_free_count + cnt.v_cache_count >= cnt.v_free_min))) {
			vm_pages_needed = 0;
			tsleep((caddr_t) &vm_pages_needed, PVM, "psleep", 0);
		}
		vm_pages_needed = 0;
		splx(s);
		cnt.v_pdwakeups++;
		vm_pager_sync();
		vm_pageout_scan();
		vm_pager_sync();
		wakeup((caddr_t) &cnt.v_free_count);
		wakeup((caddr_t) kmem_map);
	}
}

#ifndef NO_SWAPPING
static void
vm_req_vmdaemon()
{
	static int lastrun = 0;

	if ((ticks > (lastrun + hz)) || (ticks < lastrun)) {
		wakeup((caddr_t) &vm_daemon_needed);
		lastrun = ticks;
	}
}

void
vm_daemon()
{
	vm_object_t object;
	struct proc *p;

	(void) spl0();

	while (TRUE) {
		tsleep((caddr_t) &vm_daemon_needed, PUSER, "psleep", 0);
		if( vm_pageout_req_swapout) {
			swapout_threads();
			vm_pageout_req_swapout = 0;
		}
		/*
		 * scan the processes for exceeding their rlimits or if
		 * process is swapped out -- deactivate pages
		 */

		for (p = (struct proc *) allproc; p != NULL; p = p->p_next) {
			quad_t limit;
			vm_offset_t size;

			/*
			 * if this is a system process or if we have already
			 * looked at this process, skip it.
			 */
			if (p->p_flag & (P_SYSTEM | P_WEXIT)) {
				continue;
			}
			/*
			 * if the process is in a non-running type state,
			 * don't touch it.
			 */
			if (p->p_stat != SRUN && p->p_stat != SSLEEP) {
				continue;
			}
			/*
			 * get a limit
			 */
			limit = qmin(p->p_rlimit[RLIMIT_RSS].rlim_cur,
			    p->p_rlimit[RLIMIT_RSS].rlim_max);

			/*
			 * let processes that are swapped out really be
			 * swapped out set the limit to nothing (will force a
			 * swap-out.)
			 */
			if ((p->p_flag & P_INMEM) == 0)
				limit = 0;	/* XXX */

			size = p->p_vmspace->vm_pmap.pm_stats.resident_count * NBPG;
			if (limit >= 0 && size >= limit) {
				vm_pageout_map_deactivate_pages(&p->p_vmspace->vm_map,
					(u_int) (limit >> PAGE_SHIFT));
			}
		}
	}
}
#endif /* !NO_SWAPPING */
