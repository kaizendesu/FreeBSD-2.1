# Walkthrough of FreeBSD 2.1's Page Fault Code

## Contents

1. Code Flow
2. Reading Checklist
3. Important Data Structures
4. Code Walkthrough

## Code Flow

```txt
_alltraps
	trap
		trap_pfault
			vm_map_pmap
			vm_fault
				vm_map_lookup
					vm_map_lookup_entry
					vm_object_shadow
				vnode_pager_lock
				vm_page_lookup
				vm_page_unqueue
				vm_page_activate
				vm_pager_has_page
					swap_pager_haspage
					_swap_pager_haspage
					vnode_pager_haspage
						incore
				vm_page_alloc
					vm_page_remove
					vm_page_insert
				vm_fault_additional_pages
					vm_fault_page_lookup
				vm_pager_get_pages
					vm_page_free
					swap_pager_getpage
					vnode_pager_getpage
						vnode_pager_input
							vnode_pager_freepage
							vnode_pager_input_smlfs
								vm_pager_map_page
									kmem_alloc_wait
									pmap_kenter
								vm_page_bits
								vnode_pager_addr
									ufs_bmap
								ufs_strategy
									wdstrategy
								vm_pager_unmap_page
				vm_page_zero_fill
					pmap_zero_page
						pmap_update
				vm_page_copy
					pmap_copy_page
						pmap_update
				vm_object_collapse
				pmap_enter
				vm_page_wire
				vm_page_unwire
			pmap_use_pt
			pmap_unuse_pt
	userret
```

## Reading Checklist

This section lists the relevant functions for the walkthrough by filename,
where each function per filename is listed in the order that it is called.

* The first '+' means that I have read the code or have a general idea of what it does.
* The second '+' means that I have read the code closely and heavily commented it.
* The third '+' means that I have read through the doe again with a focus on the bigger picture.
* The fourth '+' means that I have added it to this document's code walkthrough.

```txt
File: exception.s
	_alltraps					++--

File: trap.c
	trap						++--
	trap_pfault					++-+
	userret						++--

File: vm_fault.c
	vm_fault					+---
	vm_fault_additional_pages	+---
	vm_fault_page_lookup		----

File: vm_map.c
	vm_map_lookup				++--
	vm_map_lookup_entry			++--

File: vm_object.c
	vm_object_shadow			++--
	vm_object_collapse			----

File: vnode_pager.c
	vnode_pager_lock			++--
	vnode_pager_getpage			++--
	vnode_pager_input			++--
	vnode_pager_freepage		++--
	vnode_pager_addr			++--

File: vm_page.c
	vm_page_lookup				++--
	vm_page_alloc				++--
	vm_page_remove				++--
	vm_page_insert				++--
	vm_page_unqueue				++--
	vm_page_activate			----
	vm_page_alloc				++--
	vm_page_free				++--
	vm_page_zero_fill			++--
	vm_page_copy				++--
	vm_page_bits				+---
	vm_page_wire				----
	vm_page_unwire				----

File: vm_pager.c
	vm_pager_has_page			++--
	vm_pager_get_pages			++--
	vm_pager_map_page			++--
	vm_pager_unmap_page			++--

File: swap_pager.c
	swap_pager_haspage			++--
	_swap_pager_haspage			++--
	swap_pager_getpage			++--
	swap_pager_input			----

File: vfs_bio.c
	incore						++--

File: vm_kern.c
	kmem_alloc_wait				++--

File: ufs_bmap.c
	ufs_bmap					+---

File: ufs_vnops
	ufs_strategy				++--

File: wd.c
	wdstrategy					----

File: pmap.c
	pmap_zero_page				++--
	pmap_copy_page				++--
	pmap_kenter					++--
	pmap_enter					----
	pmap_use_pt					++--
	pmap_unuse_pt				----

File: cpufunc.h
	pmap_update					++--
```

## Important Data Structures

### *trapframe* Structure

```c
/*
 * Exception/Trap Stack Frame
 */
struct trapframe {
	int	tf_es;
	int	tf_ds;
	int	tf_edi;
	int	tf_esi;
	int	tf_ebp;
	int	tf_isp;
	int	tf_ebx;
	int	tf_edx;
	int	tf_ecx;
	int	tf_eax;
	int	tf_trapno;
	/* below portion defined in 386 hardware */
	int	tf_err;
	int	tf_eip;
	int	tf_cs;
	int	tf_eflags;
	/* below only when transitting rings (e.g. user to kernel) */
	int	tf_esp;
	int	tf_ss;
};
```

### *proc* Structure

```c
/* From /sys/sys/proc.h */

/*
 * Description of a process.
 *
 * This structure contains the information needed to manage a thread of
 * control, known in UN*X as a process; it has references to substructures
 * containing descriptions of things that the process uses, but may share
 * with related processes.  The process structure and the substructures
 * are always addressible except for those marked "(PROC ONLY)" below,
 * which might be addressible only on a processor on which the process
 * is running.
 */
struct	proc {
	struct	proc *p_forw;		/* Doubly-linked run/sleep queue. */
	struct	proc *p_back;
	struct	proc *p_next;		/* Linked list of active procs */
	struct	proc **p_prev;		/*    and zombies. */

	/* substructures: */
	struct	pcred *p_cred;		/* Process owner's identity. */
	struct	filedesc *p_fd;		/* Ptr to open files structure. */
	struct	pstats *p_stats;	/* Accounting/statistics (PROC ONLY). */
	struct	plimit *p_limit;	/* Process limits. */
	struct	vmspace *p_vmspace;	/* Address space. */
	struct	sigacts *p_sigacts;	/* Signal actions, state (PROC ONLY). */

#define	p_ucred		p_cred->pc_ucred
#define	p_rlimit	p_limit->pl_rlimit

	int	p_flag;			/* P_* flags. */
	char	p_stat;			/* S* process status. */
	char	p_pad1[3];

	pid_t	p_pid;			/* Process identifier. */
	struct	proc *p_hash;	 /* Hashed based on p_pid for kill+exit+... */
	struct	proc *p_pgrpnxt; /* Pointer to next process in process group. */
	struct	proc *p_pptr;	 /* Pointer to process structure of parent. */
	struct	proc *p_osptr;	 /* Pointer to older sibling processes. */

/* The following fields are all zeroed upon creation in fork. */
#define	p_startzero	p_ysptr
	struct	proc *p_ysptr;	 /* Pointer to younger siblings. */
	struct	proc *p_cptr;	 /* Pointer to youngest living child. */
	pid_t	p_oppid;	 /* Save parent pid during ptrace. XXX */
	int	p_dupfd;	 /* Sideways return value from fdopen. XXX */

	/* scheduling */
	u_int	p_estcpu;	 /* Time averaged value of p_cpticks. */
	int	p_cpticks;	 /* Ticks of cpu time. */
	fixpt_t	p_pctcpu;	 /* %cpu for this process during p_swtime */
	void	*p_wchan;	 /* Sleep address. */
	char	*p_wmesg;	 /* Reason for sleep. */
	u_int	p_swtime;	 /* Time swapped in or out. */
	u_int	p_slptime;	 /* Time since last blocked. */

	struct	itimerval p_realtimer;	/* Alarm timer. */
	struct	timeval p_rtime;	/* Real time. */
	u_quad_t p_uticks;		/* Statclock hits in user mode. */
	u_quad_t p_sticks;		/* Statclock hits in system mode. */
	u_quad_t p_iticks;		/* Statclock hits processing intr. */

	int	p_traceflag;		/* Kernel trace points. */
	struct	vnode *p_tracep;	/* Trace to vnode. */

	int	p_siglist;		/* Signals arrived but not delivered. */

	struct	vnode *p_textvp;	/* Vnode of executable. */

	char	p_lock;			/* Process lock count. */
	char	p_pad2[3];		/* alignment */
	long	p_spare[2];		/* Pad to 256, avoid shifting eproc. XXX */

/* End area that is zeroed on creation. */
#define	p_endzero	p_startcopy

/* The following fields are all copied upon creation in fork. */
#define	p_startcopy	p_sigmask

	sigset_t p_sigmask;	/* Current signal mask. */
	sigset_t p_sigignore;	/* Signals being ignored. */
	sigset_t p_sigcatch;	/* Signals being caught by user. */

	u_char	p_priority;	/* Process priority. */
	u_char	p_usrpri;	/* User-priority based on p_cpu and p_nice. */
	char	p_nice;		/* Process "nice" value. */
	char	p_comm[MAXCOMLEN+1];

	struct 	pgrp *p_pgrp;	/* Pointer to process group. */

	struct 	sysentvec *p_sysent; /* System call dispatch information. */

	struct	rtprio p_rtprio;	/* Realtime priority. */
/* End area that is copied on creation. */
#define	p_endcopy	p_thread
	int	p_thread;	/* Id for this "thread"; Mach glue. XXX */
	struct	user *p_addr;	/* Kernel virtual addr of u-area (PROC ONLY). */
	struct	mdproc p_md;	/* Any machine-dependent fields. */

	u_short	p_xstat;	/* Exit status for wait; also stop signal. */
	u_short	p_acflag;	/* Accounting flags. */
	struct	rusage *p_ru;	/* Exit information. XXX */
};
```

### *vm\_map\_entry* Structure

```c
/* From /sys/vm/vm_map.h */

/*
 *	Objects which live in maps may be either VM objects, or
 *	another map (called a "sharing map") which denotes read-write
 *	sharing with other maps.
 */

union vm_map_object {
	struct vm_object *vm_object;	/* object object */
	struct vm_map *share_map;		/* share map */
	struct vm_map *sub_map;			/* belongs to another map */
};

/*
 *	Address map entries consist of start and end addresses,
 *	a VM object (or sharing map) and offset into that object,
 *	and user-exported inheritance and protection information.
 *	Also included is control information for virtual copy operations.
 */
struct vm_map_entry {
	struct vm_map_entry *prev;	/* previous entry */
	struct vm_map_entry *next;	/* next entry */
	vm_offset_t start;			/* start address */
	vm_offset_t end;			/* end address */
	union vm_map_object object;	/* object I point to */
	vm_offset_t offset;			/* offset into object */
	boolean_t is_a_map:1,		/* Is "object" a map? */
	 is_sub_map:1,				/* Is "object" a submap? */
	/* Only in sharing maps: */
	 copy_on_write:1,			/* is data copy-on-write */
	 needs_copy:1;				/* does object need to be copied */
	/* Only in task maps: */
	vm_prot_t protection;		/* protection code */
	vm_prot_t max_protection;	/* maximum protection */
	vm_inherit_t inheritance;	/* inheritance */
	int wired_count;			/* can be paged if = 0 */
};
```

### *vm\_object* Structure

```c
/* From /sys/vm/vm_object.h */

struct vm_object {
	struct pglist memq;		/* Resident memory */
	TAILQ_HEAD(rslist, vm_object) reverse_shadow_head; /* objects that this is a shadow for */
	TAILQ_ENTRY(vm_object) object_list; /* list of all objects */
	TAILQ_ENTRY(vm_object) reverse_shadow_list; /* chain of objects that are shadowed */
	TAILQ_ENTRY(vm_object) cached_list; /* for persistence */
	vm_size_t size;			/* Object size */
	int ref_count;			/* How many refs?? */
	u_short flags;			/* see below */
	u_short paging_in_progress;	/* Paging (in or out) so don't collapse or destroy */
	int resident_page_count;	/* number of resident pages */
	vm_pager_t pager;		/* Where to get data */
	vm_offset_t paging_offset;	/* Offset into paging space */
	struct vm_object *shadow;	/* My shadow */
	vm_offset_t shadow_offset;	/* Offset in shadow */
	struct vm_object *copy;		/* Object that holds copies of my changed pages */
	vm_offset_t last_read;		/* last read in object -- detect seq behavior */
};
```

### *vm_page* Structure

```c
/*
 *	Management of resident (logical) pages.
 *
 *	A small structure is kept for each resident
 *	page, indexed by page number.  Each structure
 *	is an element of several lists:
 *
 *		A hash table bucket used to quickly
 *		perform object/offset lookups
 *
 *		A list of all pages for a given object,
 *		so they can be quickly deactivated at
 *		time of deallocation.
 *
 *		An ordered list of pages due for pageout.
 *
 *	In addition, the structure contains the object
 *	and offset to which this page belongs (for pageout),
 *	and sundry status bits.
 *
 *	Fields in this structure are locked either by the lock on the
 *	object that the page belongs to (O) or by the lock on the page
 *	queues (P).
 */

TAILQ_HEAD(pglist, vm_page);

struct vm_page {
	TAILQ_ENTRY(vm_page) pageq;	/* queue info for FIFO queue or free list (P) */
	TAILQ_ENTRY(vm_page) hashq;	/* hash table links (O) */
	TAILQ_ENTRY(vm_page) listq;	/* pages in same object (O) */

	vm_object_t object;		/* which object am I in (O,P) */
	vm_offset_t offset;		/* offset into object (O,P) */
	vm_offset_t phys_addr;		/* physical address of page */

	u_short wire_count;		/* wired down maps refs (P) */
	u_short flags;			/* see below */
	short hold_count;		/* page hold count */
	u_short act_count;		/* page usage count */
	u_short bmapped;		/* number of buffers mapped */
	u_short busy;			/* page busy count */
	u_short valid;			/* map of valid DEV_BSIZE chunks */
	u_short dirty;			/* map of dirty DEV_BSIZE chunks */
};

/*
 * These are the flags defined for vm_page.
 *
 * Note: PG_FILLED and PG_DIRTY are added for the filesystems.
 */
#define	PG_INACTIVE	0x0001		/* page is in inactive list (P) */
#define	PG_ACTIVE	0x0002		/* page is in active list (P) */
#define	PG_BUSY		0x0010		/* page is in transit (O) */
#define	PG_WANTED	0x0020		/* someone is waiting for page (O) */
#define	PG_TABLED	0x0040		/* page is in VP table (O) */
#define	PG_COPYONWRITE	0x0080		/* must copy page before changing (O) */
#define	PG_FICTITIOUS	0x0100		/* physical page doesn't exist (O) */
#define	PG_WRITEABLE	0x0200		/* page is mapped writeable */
#define PG_MAPPED	0x0400		/* page is mapped */
#define PG_REFERENCED	0x1000		/* page has been referenced */
#define	PG_CACHE	0x4000		/* On VMIO cache */
#define	PG_FREE		0x8000		/* page is in free list */
```

### *vm\_pager* and *pagerops* Structures

```c
/* From /sys/vm/vm_pager.h */
 
struct pager_struct {
	TAILQ_ENTRY(pager_struct) pg_list;	/* links for list management */
	void *pg_handle;		/* ext. handle (vp, dev, fp) */
	int pg_type;			/* type of pager */
	struct pagerops *pg_ops;	/* pager operations */
	void *pg_data;			/* private pager data */
};

/* pager types */
#define PG_DFLT		-1
#define	PG_SWAP		0
#define	PG_VNODE	1
#define PG_DEVICE	2

/* flags */
#define PG_CLUSTERGET	1
#define PG_CLUSTERPUT	2

struct pagerops {
	void (*pgo_init) __P((void));		/* Initialize pager. */
	vm_pager_t(*pgo_alloc) __P((void *, vm_size_t, vm_prot_t, vm_offset_t));	/* Allocate pager. */
	void (*pgo_dealloc) __P((vm_pager_t));	/* Disassociate. */
	int (*pgo_getpage) __P((vm_pager_t, vm_page_t, boolean_t));
	int (*pgo_getpages) __P((vm_pager_t, vm_page_t *, int, int, boolean_t));	/* Get (read) page. */
	int (*pgo_putpage) __P((vm_pager_t, vm_page_t, boolean_t));
	int (*pgo_putpages) __P((vm_pager_t, vm_page_t *, int, boolean_t, int *)); /* Put (write) page. */
	boolean_t(*pgo_haspage) __P((vm_pager_t, vm_offset_t)); /* Does pager have page? */
};

#define	VM_PAGER_GET(pg, m, s)		(*(pg)->pg_ops->pgo_getpage)(pg, m, s)
#define	VM_PAGER_GET_MULTI(pg, m, c, r, s)	(*(pg)->pg_ops->pgo_getpages)(pg, m, c, r, s)
```

## Code Walkthrough

### Pseudo Code Descriptions

\_**alltraps**:

**trap**:

**trap_pfault**:

**grow**:

**vm_map_pmap**:

**vm_fault**:

1. Calls vm\_map\_lookup to obtain the backing store object and offset of the faulting virtual address.
2. Locks the first object and obtains a pointer to its vnode by calling vnode\_pager\_lock.
3. Locks the first object, increments its ref count, and increments paging\_in\_progress.
4. While Loop: Searches for the page by calling vm\_page\_lookup with its object/offset pair.
	* Found Hashed Page: Checks the pg's flag for PG\_BUSY and the page's busy count, calling tsleep if they are set.
	* Found Hashed Page: Calls vm\_page\_unqueue so that the pageout daemon cannot tamper with it
	* Found Hashed Page: Calls vm\_page\_activate if the pg is cached and there is not enough free and cached pgs, and then calls VM\_WAIT before restarting the loop. 
	* Found Hashed Page: Sets PG\_BUSY and jumps to readrest if there are any invalid disk blks in the pg.
	* Found Hashed page: Breaks out of the while loop.
5. While Loop: Calls vm\_pager\_has\_page if the object's pager is a swap pager and the swap space is not full.
6. While Loop: Calls vm\_page\_alloc to allocate a page in the current object and set it to PG\_BUSY.
7. While Loop: If the object has a vnode/swap pager and we are not changing the page's wiring it...
	* Unlocks the object
	* Calls vm\_fault\_additional\_pages to see if there are any additional pages we can fault in for space locality
	* Calls vm\_pager\_get\_pages to obtain the paes from disk/swap

**vm_map_lookup**:

1. Locks the vm map.
2. Checks if the vm map's hint contains the vaddr, and if it doesn't it calls vm\_map\_lookup\_entry to obtain the preceding entry.
3. If the entry is a submap, sets map to the submap, frees the old map, and restarts the search.
4. Checks if the fault type matches the protections on the entry, returning KERN\_PROTECTION\_FAILURE if fault type is not a subset of them.
5. Checks if the entry's VM object is actually a share map, assigning share\_map and calculating share\_offset if it is and calling vm\_map\_lookup\_entry to search for the backing object. Otherwise, share\_map and share\_offset are map and vaddr respectively.
6. Creates a shadow object for writing pg faults by calling vm\_object\_shadow and assigning entry-\>needs\_copy to FALSE. Otherwise, clear VM\_PROT\_WRITE from prot to prevent future writes.
7. Creates the map entry's object if it is NULL.
8. Assigns the final offset, object, and protections to the IN/OUT arguments offset, object, and prot respectively.
9. Returns KERN\_SUCCESS.

**vm_map_lookup_entry**:

1. Locks the vm map's hint and assigns the hint to cur.
2. Sets cur to cur-\>next if the hint is &map-\>header (unassigned hint). 
3. Checks if the cur entry precedes the address, setting \(entry = cur and returning TRUE if it does. 
4. Linearly searches from the hint to the end of the map if the address we are searching is >= cur-\>start and searches from the beginning of the map to the hint otherwise.
5. Saves the current entry as the hint When cur-\>start <= address < cur-\>end, assigns \(entry = cur and returns TRUE.
6. If cur-\>end > address, assigns \*entry = cur-\>prev, saves the previous entry as the hint, and returns FALSE.

**vm_object_shadow**:

1. Allocates a new object by passing length arg to vm\_object\_allocate.
2. Sets the source object as the backing object of the new object by assigning result-\>shadow = source.
3. Sets the new object's offset into its backing object as the offset arg.
4. Updates the IN/OUT args offset and object with 0 and the new object respectively.

**vnode_pager_lock**:

1. Searches through the chain of shadow objects until it finds an entry with a non-NULL vnode pager.
2. Retrieves the vnode pager pointer from the object-\>pager-\>pg\_data.
3. Calls VOP\_LOCK to lock the vnode pager.
4. Returns the vnode pointer from the vnode pager.

**vm_page_lookup:** Looks up the object/offset pair in the vm\_page\_hash table, checks whether this entry is valid, and returns the vm\_page if its entry and offset matches the one used to find it in the hash table.

**vm_page_unqueue**: Removes the pg from the page queue specified by the mem-\>flags field and decrements that queue's count.

**vm_page_activate**:

**vm_pager_has_page**: Checks if the pager is NULL before calling accessing its pg\_ops to call the appropriate \(\_haspage operation.

**swap_pager_haspage**: Calls \_swap\_pager\_haspage by passing pager-\>pg\+data and returns its return value.

\_**swap_pager_haspage**: Uses 2D row/col arithmetic to determine whether the swap blk for the pg's offset is empty or not, returning TRUE if this region is not empty.

**vnode_pager_haspage**: Divides the offset by the mounted filesystem's block size to get the blkno, calls incore by passing this blkno, and calls ufs\_bmap if incore returns FALSE.

**incore**: Uses the vnode/blkno pair to search the buffer hash table.

**vm_page_alloc**:

1. Upgrades the allocation class for the page daemon if it isn't VM\_ALLOC\_INTERRUPT.
2. Locks the free page queue.
3. Switches on the allocation class, determing whether there is enough pgs in each pg queue to allocate the request.
	* VM\_ALLOC\_NORMAL takes a pg from the free pg queue if free\_count > free\_reserved, otherwise it tries to take the LRU pg from the pg cache
	* VM\_ALLOC\_SYSTEM takes a pg from the free pg queue if the free\_count >= interrupt free min and either free\_count >= free\_reserved or cache\_count == 0. Otherwise, tries to take the LRU pg from the pg cache.
	* VM\_ALLOC\_INTERRUPT takes pgs from the free pg queue until its all gone
	* Calls pagedaemon\_wakeup if any of these switch cases fail to obtain a pg.
4. Unlocks the free pg queue.
5. Sets PG\_BUSY and all other fields to 0.
6. Calls vm\_page\_insert to insert the pg into the object.
7. Calls pagedaemon\_wakeup if free\_count + cache\_count < free\_min or free\_count < pageout\_free\_min.
8. Returns the pg. 

**vm_page_remove**;

1. Returns early if PG\_TABLED is not set.
2. Locks the vm\_page\_hash table, removes the page from it, and unlocks the table.
3. Removes the page from the object's pg queue.
4. Decrements the resident\_page\_count and clears PG\_TABLED.

**vm_page_insert**:

1. Checks that the pg is within the vm\_page\_array and that its flags are not invalid.
2. Sets the page's object and offset to the object and offset args passed to the function.
3. Locks the vm\_page\_buckets hash table, inserts the page, and unlocks the table.
4. Inserts the pg at the tail of the object's pg queue.
5. Sets PG\_TABLED and increments resident\_page\_count.  

**vm_fault_additional_pages**: Checks whether there is enough memory to fault in ra/rb pages and returns a pg array of pgs to fault along with the index of the req pg.

**vm_fault_page_lookup**:

**vm_pager_get_pages**:

1. If the pager is NULL, loops through the marray:
	* Calls PAGE\_WAKEUP and vm\_page\_free for ra/rb pgs.
	* Calls vm\_page\_zero\_fill for the req page.
	* Returns VM\_PAGER\_OK.
2. If the pager does not have the pgo\_getpages op, calls PAGE\_WAKEUP on all ra/rb pages and pgo\_getpage on the req page. Otherwise, calls pgo\_getpages.

**swap_pager_getpage**: Assigns pg to a marray and uses it to call swap\_pager\_input.

**vnode_pager_getpage**: Assigns pg to a marray and uses it to call vnode\_pager\_input.

**vnode_pager_input**:

1. Calls vnode\_pager\_freepage on every pg in the marray that isn't the required page.
2. Increments vnodein and vnodepgsin.
3. Calls vnode\_pager\_input\_smlfs and returns. 

**vnode_pager_freepage**: Clears PG\_BUSY, wakes up any processes sleeping on the page, and calls vm\_page\_free.

**vnode_pager_input_smlfs**:

1. Calls vm\_pager\_map\_page to allocate a free page of memory, map it into the kernel va space, and obtain its kva.
2. For each file system blk in the file:
	* Calls vm\_page\_bits to check if that block of the page is valid. If the block is valid, we continue.
	* Calls vnode\_pager\_addr to obtain the file addr of the filesystem block.
	* Calls ufs\_strategy.

**vm_pager_map_page**: Calls kmem\_alloc\_wait to allocate a free page from the pager's submap, calls pmap\_kenter to insert the pg into the kva space, and returns the va of the page.

**kmem_alloc_wait**:

1. Rounds the allocation size to the nearest page
2. For Loop: Calls vm\_map\_findspace to search for space in the map, breaks if it is successful, inserts the allocation with vm\_map\_insert, and returns the address of the allocation.
3. For Loop: If it fails to find space in the map, it checks to see if the map will ever have enough space using vm\_map\_max/min, and if the map is too small for the allocation it returns 0.
4. For Loop: Unlocks the map and tsleep's until new memory is available int he submap and loops.

**vm_page_bits**: Returns the valid bit for a given disk block in a physical page.

**vnode_pager_addr**:

1. Calculates the logical blk nb and logical offset from the address arg.
2. Calls ufs\_bmap to convert the logical blk nb to the physical disk blk nb.
3. Assigns rtaddress to the physical disk blk nb plus the logical offset in 512 byte units.
4. Returns rtaddress.

**ufs_bmap**:

**ufs_strategy**:

1. Obtains the inode from the buf arg's vnode to ensure the vnode type is not VBLK or VCHR.
2. Calls ufs\_bmap to calculate the physical blk nb if b\_blkno == b\_lblkno.
3. Calls vop\_strategy from the vnode's vnodeops structure.
4. Returns 0.

**vm_pager_unmap_page**:

**vm_page_free**:

1. Calls vm\_page\_remove to remove the pg from the vm\_page\_hash table, remove it from the object's memq, decrements resident\_page\_count, and clears PG\_TABLED.
2. Calls vm\_page\_unqueue to remove the pg from the active queue
3. Checks if it is freeing a busy or free page and panicks if it is.
4. Wakes up any processes sleeping on this page.
5. If the physical page exists:
	* Decrements the wire count
	* Marks the pg free and inserts it into the free pg queue
	* Wakes up the pageout daemon, any procs waiting on high water mark mem, and the scheduler to swap in procs.
6. Increments v\_tfree and returns.  

**vm_page_zero_fill**: Checks if the page is valid, calls pmap\_zero\_page, and sets all disk blks valid in the page.

**pmap_zero_page**: Checks if CMAP2 is busy, assigns CMAP2 the pte of the page we want to clear, calls bzero on CADDR2 to clear the page, invalidates the pte at CMAP2, and calls pmap\_update.

**vm_page_copy**: Checks if the source and destination pages are valid, calls pmap\_copy\_page, and sets all disk blks valid in the dest page.

**pmap_copy_page**: Checks if CMAP1 and CMAP2 are busy, assigns the pte of the source page to CMAP1 and the pte of the destination page to CMAP2, and calls either memcpy or bcopy to copy the pages, invalidates the ptes at CMAP1 and CMAP2, and calls pmap\_update.

**pmap_update**: Flushes the TLB by reloading the CR3 register.

**pmap_kenter**: Obtains the kernel va's pte, increments wasvalid if it is already mapped, sets the pte to point to pa, and calls pmap\_update to flush the TLB if wasvalid is set.

**vm_object_collapse**:

**pmap_enter**:

**vm_page_wire**:

**vm_page_unwire**:

**pmap_use_pt**:

**pmap_unuse_pt**:

**userret**:


### Documented Code

```c
_alltraps:
	pushal					/* push general regs */
	pushl	%ds
	pushl	%es				/* push data selectors */
alltraps_with_regs_pushed:
	movl	$KDSEL,%eax		/* switch to kernel data selector */
	movl	%ax,%ds
	movl	%ax,%es
	FAKE_MCOUNT(12*4(%esp))	/* no-op */
calltrap:
	FAKE_MCOUNT(_btrap)		/* init "from" _btrap -> calltrap */
	incl	_cnt+V_TRAP		/* incr nb of vm traps */
	orl	$SWI_AST_MASK,_cpl	/* something about cpu prio lvl */
	call	_trap			/* jump to C trap() routine */
	/*
	 * There was no place to save the cpl so we have to recover it
	 * indirectly.  For traps from user mode it was 0, and for traps
	 * from kernel mode Oring SWI_AST_MASK into it didn't change it.
	 */
	subl	%eax,%eax
	testb	$SEL_RPL_MASK,TRAPF_CS_OFF(%esp)
	jne	1f
	movl	_cpl,%eax
1:
	/*
	 * Return via _doreti to handle ASTs.  Have to change trap frame
	 * to interrupt frame.
	 */
	pushl	%eax
	subl	$4,%esp
	incb	_intr_nesting_level
	MEXITCOUNT
	jmp	_doreti

int
trap_pfault(frame, usermode)
	struct trapframe *frame;
	int usermode;
{
	vm_offset_t va;
	struct vmspace *vm = NULL;
	vm_map_t map = 0;
	int rv = 0;
	vm_prot_t ftype;
	int eva;
	struct proc *p = curproc;

	/*
	 * Obtain addr that caused the pg fault from
	 * CR2 register.
	 *
	 * From /sys/i386/include/cpufunc.h
	 *
	 * rcr2(void) {
	 * 		u_long	data;
	 * __asm __volatile("movl %%cr2,%0" : "=r" (data));
	 * return (data);
	 * }
	 */
	eva = rcr2();

	/* Pg align eva */
	va = trunc_page((vm_offset_t)eva);

	if (va >= KERNBASE) {
		/*
		 * Don't allow user-mode faults in kernel address space.
		 */
		if (usermode)
			goto nogo;

		map = kernel_map;
	} else {
		/*
		 * This is a fault on non-kernel virtual memory.
		 * vm is initialized above to NULL. If curproc is NULL
		 * or curproc->p_vmspace is NULL the fault is fatal.
		 */
		if (p != NULL)
			vm = p->p_vmspace;

		if (vm == NULL)
			goto nogo;

		map = &vm->vm_map;
	}

	/* Set type of pg fault */
	if (frame->tf_err & PGEX_W)
		ftype = VM_PROT_READ | VM_PROT_WRITE;
	else
		ftype = VM_PROT_READ;

	if (map != kernel_map) {
		vm_offset_t v;
		vm_page_t ptepg;
		/*
		 * Keep swapout from messing with us during this
		 *	critical time.
		 */
		++p->p_lock;
		/*
		 * Grow the stack if necessary
		 */
		if ((caddr_t)va > vm->vm_maxsaddr
			/* (caddr_t)va < (caddr_t)VM_MAXUSER_ADDRESS */
		    && (caddr_t)va < (caddr_t)USRSTACK) {
			if (!grow(p, va)) {
				rv = KERN_FAILURE;
				--p->p_lock;
				goto nogo;
			}
		}
		/*
		 * Check if page table is mapped, if not,
		 * fault it first
		 */
		v = (vm_offset_t) vtopte(va);	/* v is va's pte */

		/* Fault the pte only if needed:
		 * 
		 * Why does dereferencing this not cause
		 * a page fault? 
		 */
		if (*((int *)vtopte(v)) == 0)
			(void) vm_fault(map, trunc_page(v), VM_PROT_WRITE, FALSE);
		/*
		 * Incr the ref count of the vm_page corresponding to
		 * the page tbl pg containing va's pte.
		 *
		 * #define vm_map_pmap(map) ((map)->pmap)
		 */ 
		pmap_use_pt( vm_map_pmap(map), va);

		/* Fault in the user page: */
		rv = vm_fault(map, va, ftype, FALSE);
		/*
		 * Decr the ref count of the vm_page corresponding to
		 * the page tbl pg eontaining va's pte.
		 */
		pmap_unuse_pt( vm_map_pmap(map), va);

		--p->p_lock;
	} else {
		/*
		 * Since we know that kernel virtual address addresses
		 * always have pte pages mapped, we just have to fault
		 * the page.
		 */
		rv = vm_fault(map, va, ftype, FALSE);
	}

	if (rv == KERN_SUCCESS)
		return (0);
nogo:
	if (!usermode) {
		if (curpcb && curpcb->pcb_onfault) {
			frame->tf_eip = (int)curpcb->pcb_onfault;
			return (0);
		}
		trap_fatal(frame);
		return (-1);
	}

	/* kludge to pass faulting virtual address to sendsig */
	frame->tf_err = eva;

	return((rv == KERN_PROTECTION_FAILURE) ? SIGBUS : SIGSEGV);
}

```
