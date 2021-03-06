/*
 * Copyright (c) 1993 Jan-Simon Pendry
 * Copyright (c) 1993 Sean Eric Fagan
 * Copyright (c) 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Jan-Simon Pendry and Sean Eric Fagan.
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
 *	@(#)procfs_mem.c	8.4 (Berkeley) 1/21/94
 *
 * $FreeBSD$
 */

/*
 * This is a lightly hacked and merged version
 * of sef's pread/pwrite functions
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <miscfs/procfs/procfs.h>
#include <vm/vm.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>

static int
procfs_rwmem(p, uio)
	struct proc *p;
	struct uio *uio;
{
	int error;
	int writing;
	struct vmspace *vm;
	int fix_prot = 0;
	vm_map_t map;
	vm_object_t object = NULL;
	vm_offset_t pageno = 0;		/* page number */

	/*
	 * if the vmspace is in the midst of being deallocated or the
	 * process is exiting, don't try to grab anything.  The page table
	 * usage in that process can be messed up.
	 */
	vm = p->p_vmspace;
	if ((p->p_flag & P_WEXIT) || (vm->vm_refcnt < 1))
		return EFAULT;
	++vm->vm_refcnt;
	/*
	 * The map we want...
	 */
	map = &vm->vm_map;

	writing = uio->uio_rw == UIO_WRITE;

	/*
	 * Only map in one page at a time.  We don't have to, but it
	 * makes things easier.  This way is trivial - right?
	 */
	do {
		vm_map_t tmap;
		vm_offset_t kva = 0;
		vm_offset_t uva;
		int page_offset;		/* offset into page */
		vm_map_entry_t out_entry;
		vm_prot_t out_prot;
		vm_page_t m;
		boolean_t wired, single_use;
		vm_offset_t off;
		u_int len;

		fix_prot = 0;
		object = NULL;

		uva = (vm_offset_t) uio->uio_offset;

		/*
		 * Get the page number of this segment.
		 */
		pageno = trunc_page(uva);
		page_offset = uva - pageno;

		/*
		 * How many bytes to copy
		 */
		len = min(PAGE_SIZE - page_offset, uio->uio_resid);

		if (uva >= VM_MAXUSER_ADDRESS) {
			if (writing || (uva >= (VM_MAXUSER_ADDRESS + UPAGES * PAGE_SIZE))) {
				error = 0;
				break;
			}
		}

		/*
		 * Check the permissions for the area we're interested
		 * in.
		 */
		if (writing) {
			fix_prot = !vm_map_check_protection(map, pageno,
					pageno + PAGE_SIZE, VM_PROT_WRITE);

			if (fix_prot) {
				/*
				 * If the page is not writable, we make it so.
				 * XXX It is possible that a page may *not* be
				 * read/executable, if a process changes that!
				 * We will assume, for now, that a page is either
				 * VM_PROT_ALL, or VM_PROT_READ|VM_PROT_EXECUTE.
				 */
				error = vm_map_protect(map, pageno,
					pageno + PAGE_SIZE, VM_PROT_ALL, 0);
				if (error) {
					/*
					 * We don't have to undo something
					 * that didn't work, so we clear the
					 * flag.
					 */
					fix_prot = 0;
					break;
				}
			}
		}

		/*
		 * Now we need to get the page.  out_entry, out_prot, wired,
		 * and single_use aren't used.  One would think the vm code
		 * would be a *bit* nicer...  We use tmap because
		 * vm_map_lookup() can change the map argument.
		 */
		tmap = map;
		error = vm_map_lookup(&tmap, pageno,
			      writing ? VM_PROT_WRITE : VM_PROT_READ,
			      &out_entry, &object, &off, &out_prot,
			      &wired, &single_use);

		if (error) {
			/*
			 * Make sure that there is no residue in 'object' from
			 * an error return on vm_map_lookup.
			 */
			object = NULL;
			break;
		}

		/*
		 * We're done with tmap now.
		 * But reference the object first, so that we won't loose
		 * it.
		 */
		vm_object_reference(object);
		vm_map_lookup_done(tmap, out_entry);

		/*
		 * Fault the page in...
		 */
		if (writing && object->shadow) {
			m = vm_page_lookup(object, off);
			if (m == 0 || (m->flags & PG_COPYONWRITE)) {
				error = vm_fault(map, pageno,
					VM_PROT_WRITE, FALSE);
				break;
			}
		}

		/* Find space in kernel_map for the page we're interested in */
		error = vm_map_find(kernel_map, object, off, &kva, PAGE_SIZE, 1);
		if (error) {
			break;
		}

		/*
		 * Mark the page we just found as pageable.
		 */
		error = vm_map_pageable(kernel_map, kva,
				kva + PAGE_SIZE, 0);
		if (error) {
			vm_map_remove(kernel_map, kva, kva + PAGE_SIZE);
			object = NULL;
			break;
		}

		/*
		 * Now do the i/o move.
		 */
		error = uiomove((caddr_t)(kva + page_offset),
				len, uio);

		/*
		 * vm_map_remove gets rid of the object reference, so
		 * we need to get rid of our 'object' pointer if there
		 * is subsequently an error.
		 */
		vm_map_remove(kernel_map, kva, kva + PAGE_SIZE);
		object = NULL;

		/*
		 * Undo the protection 'damage'.
		 */
		if (fix_prot) {
			vm_map_protect(map, pageno, pageno + PAGE_SIZE,
				VM_PROT_READ|VM_PROT_EXECUTE, 0);
			fix_prot = 0;
		}
	} while (error == 0 && uio->uio_resid > 0);

	if (object)
		vm_object_deallocate(object);

	if (fix_prot)
		vm_map_protect(map, pageno, pageno + PAGE_SIZE,
				VM_PROT_READ|VM_PROT_EXECUTE, 0);

	vmspace_free(vm);
	return (error);
}

/*
 * Copy data in and out of the target process.
 * We do this by mapping the process's page into
 * the kernel and then doing a uiomove direct
 * from the kernel address space.
 */
int
procfs_domem(curp, p, pfs, uio)
	struct proc *curp;
	struct proc *p;
	struct pfsnode *pfs;
	struct uio *uio;
{
	int error;

	if (uio->uio_resid == 0)
		return (0);

 	/*
 	 * XXX
 	 * We need to check for KMEM_GROUP because ps is sgid kmem;
 	 * not allowing it here causes ps to not work properly.  Arguably,
 	 * this is a bug with what ps does.  We only need to do this
 	 * for Pmem nodes, and only if it's reading.  This is still not
 	 * good, as it may still be possible to grab illicit data if
 	 * a process somehow gets to be KMEM_GROUP.  Note that this also
 	 * means that KMEM_GROUP can't change without editing procfs.h!
 	 * All in all, quite yucky.
 	 */
  
	if (!CHECKIO(curp, p) &&
 	    !(curp->p_cred->pc_ucred->cr_gid == KMEM_GROUP &&
 	      uio->uio_rw == UIO_READ))
  		return EPERM;
 
	error = procfs_rwmem(p, uio);

	return (error);
}

/*
 * Given process (p), find the vnode from which
 * it's text segment is being executed.
 *
 * It would be nice to grab this information from
 * the VM system, however, there is no sure-fire
 * way of doing that.  Instead, fork(), exec() and
 * wait() all maintain the p_textvp field in the
 * process proc structure which contains a held
 * reference to the exec'ed vnode.
 */
struct vnode *
procfs_findtextvp(p)
	struct proc *p;
{
	return (p->p_textvp);
}


#ifdef probably_never
/*
 * Given process (p), find the vnode from which
 * it's text segment is being mapped.
 *
 * (This is here, rather than in procfs_subr in order
 * to keep all the VM related code in one place.)
 */
struct vnode *
procfs_findtextvp(p)
	struct proc *p;
{
	int error;
	vm_object_t object;
	vm_offset_t pageno;		/* page number */

	/* find a vnode pager for the user address space */

	for (pageno = VM_MIN_ADDRESS;
			pageno < VM_MAXUSER_ADDRESS;
			pageno += PAGE_SIZE) {
		vm_map_t map;
		vm_map_entry_t out_entry;
		vm_prot_t out_prot;
		boolean_t wired, single_use;
		vm_offset_t off;

		map = &p->p_vmspace->vm_map;
		error = vm_map_lookup(&map, pageno,
			      VM_PROT_READ,
			      &out_entry, &object, &off, &out_prot,
			      &wired, &single_use);

		if (!error) {
			vm_pager_t pager;

			printf("procfs: found vm object\n");
			vm_map_lookup_done(map, out_entry);
			printf("procfs: vm object = %x\n", object);

			/*
			 * At this point, assuming no errors, object
			 * is the VM object mapping UVA (pageno).
			 * Ensure it has a vnode pager, then grab
			 * the vnode from that pager's handle.
			 */

			pager = object->pager;
			printf("procfs: pager = %x\n", pager);
			if (pager)
				printf("procfs: found pager, type = %d\n", pager->pg_type);
			if (pager && pager->pg_type == PG_VNODE) {
				struct vnode *vp;

				vp = (struct vnode *) pager->pg_handle;
				printf("procfs: vp = 0x%x\n", vp);
				return (vp);
			}
		}
	}

	printf("procfs: text object not found\n");
	return (0);
}
#endif /* probably_never */
