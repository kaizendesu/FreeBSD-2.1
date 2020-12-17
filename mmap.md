# Walkthrough of FreeBSD 2.1's Memory Map System Call

## Contents

1. Code Flow
2. Reading Checklist
3. Important Data Structures
4. Code Walkthrough

## Code Flow

```txt
mmap
	vm_mmap
		ufs_getattr
		vm_pager_allocate
			vnode_pager_alloc
				vm_object_allocate
					_vm_object_allocate
				vm_object_enter
		vm_object_lookup
		vm_object_deallocate
			vm_object_remove			(bonus)
			vm_object_terminate			(bonus)
				_vm_object_page_clean	(bonus)
		vm_map_find
			vm_map_findspace
				vm_map_lookup_entry
			vm_map_insert
				vm_map_entry_create
				vm_map_entry_link
		vm_object_pmap_copy
		pmap_object_init_pt
			vm_page_lookup
			pmap_enter_quick
				pmap_remove
				get_pv_entry
				pmap_use_pt
					pmap_pte_vm_page
		vm_map_protect
			pmap_protect
		vm_map_inherit
```

## Reading Checklist

This section lists the relevant functions for the walkthrough by filename,
where each function per filename is listed in the order that it is called.

* The first '+' means that I have read the code or have a general idea of what it does.
* The second '+' means that I have read the code closely and heavily commented it.
* The third '+' means that I have read through the doe again with a focus on the bigger picture.
* The fourth '+' means that I have added it to this document's code walkthrough.

```txt
File: vm_mmap.c
	mmap					++-+
	vm_mmap					++-+

File: ufs_vnops.c
	ufs_getattr				++--

File: vm_pager.c
	vm_pager_allocate		++--

File: vnode_pager.c
	vnode_pager_alloc		++--

File: vm_object.c
	vm_object_allocate		++--
	_vm_object_allocate		++--
	vm_object_enter			+---
	vm_object_lookup		+---
	vm_object_deallocate	+---
	vm_object_remove		----
	vm_object_terminate		----
	_vm_object_page_clean	----
	vm_object_pmap_copy		++--

File: vm_map.c
	vm_map_find				++--
	vm_map_findspace		++--
	vm_map_lookup_entry		++--
	vm_map_insert			++--
	vm_map_entry_create		+---
	vm_map_entry_link		++--
	vm_map_protect			----
	vm_map_inherit			----

File: pmap.c
	pmap_object_init_pt		++--
	pmap_enter_quick		++--
	pmap_remove				----
	get_pv_entry			++--
	pmap_use_pt				++--
	pmap_pte_vm_page		++--
	pmap_protect			----

File: vm_page.c
	vm_page_lookup			++--
```

## Important Data Structures

### *vnodeop_desc* Structures

```c
/* From /sys/sys/vnode.h */

/*
 * This structure describes the vnode operation taking place.
 */
struct vnodeop_desc {
	int	vdesc_offset;		/* offset in vector--first for speed */
	char    *vdesc_name;	/* a readable name for debugging */
	int	vdesc_flags;		/* VDESC_* flags */

	/*
	 * These ops are used by bypass routines to map and locate arguments.
	 * Creds and procs are not needed in bypass routines, but sometimes
	 * they are useful to (for example) transport layers.
	 * Nameidata is useful because it has a cred in it.
	 */
	int	*vdesc_vp_offsets;	/* list ended by VDESC_NO_OFFSET */
	int	vdesc_vpp_offset;	/* return vpp location */
	int	vdesc_cred_offset;	/* cred location, if any */
	int	vdesc_proc_offset;	/* proc location, if any */
	int	vdesc_componentname_offset; /* if any */
	/*
	 * Finally, we've got a list of private data (about each operation)
	 * for each transport layer.  (Support to manage this list is not
	 * yet part of BSD.)
	 */
	caddr_t	*vdesc_transports;
};

/* From /sys/ufs/ffs/ffs_vnops.c */

/* Global vfs data structures for ufs. */
int (**ffs_vnodeop_p)();
struct vnodeopv_entry_desc ffs_vnodeop_entries[] = {
	{ &vop_default_desc, vn_default_error },
	{ &vop_lookup_desc, ufs_lookup },		/* lookup */
	{ &vop_create_desc, ufs_create },		/* create */
	{ &vop_mknod_desc, ufs_mknod },			/* mknod */
	{ &vop_open_desc, ufs_open },			/* open */
	{ &vop_close_desc, ufs_close },			/* close */
	{ &vop_access_desc, ufs_access },		/* access */
	{ &vop_getattr_desc, ufs_getattr },		/* getattr */
	{ &vop_setattr_desc, ufs_setattr },		/* setattr */
	{ &vop_read_desc, ffs_read },			/* read */
	{ &vop_write_desc, ffs_write },			/* write */
	{ &vop_ioctl_desc, ufs_ioctl },			/* ioctl */
	{ &vop_select_desc, ufs_select },		/* select */
	{ &vop_mmap_desc, ufs_mmap },			/* mmap */
	{ &vop_fsync_desc, ffs_fsync },			/* fsync */
	{ &vop_seek_desc, ufs_seek },			/* seek */
	{ &vop_remove_desc, ufs_remove },		/* remove */
	{ &vop_link_desc, ufs_link },			/* link */
	{ &vop_rename_desc, ufs_rename },		/* rename */
	{ &vop_mkdir_desc, ufs_mkdir },			/* mkdir */
	{ &vop_rmdir_desc, ufs_rmdir },			/* rmdir */
	{ &vop_symlink_desc, ufs_symlink },		/* symlink */
	{ &vop_readdir_desc, ufs_readdir },		/* readdir */
	{ &vop_readlink_desc, ufs_readlink },		/* readlink */
	{ &vop_abortop_desc, ufs_abortop },		/* abortop */
	{ &vop_inactive_desc, ufs_inactive },		/* inactive */
	{ &vop_reclaim_desc, ufs_reclaim },		/* reclaim */
	{ &vop_lock_desc, ufs_lock },			/* lock */
	{ &vop_unlock_desc, ufs_unlock },		/* unlock */
	{ &vop_bmap_desc, ufs_bmap },			/* bmap */
	{ &vop_strategy_desc, ufs_strategy },		/* strategy */
	{ &vop_print_desc, ufs_print },			/* print */
	{ &vop_islocked_desc, ufs_islocked },		/* islocked */
	{ &vop_pathconf_desc, ufs_pathconf },		/* pathconf */
	{ &vop_advlock_desc, ufs_advlock },		/* advlock */
	{ &vop_blkatoff_desc, ffs_blkatoff },		/* blkatoff */
	{ &vop_valloc_desc, ffs_valloc },		/* valloc */
	{ &vop_reallocblks_desc, ffs_reallocblks },	/* reallocblks */
	{ &vop_vfree_desc, ffs_vfree },			/* vfree */
	{ &vop_truncate_desc, ffs_truncate },		/* truncate */
	{ &vop_update_desc, ffs_update },		/* update */
	{ &vop_bwrite_desc, vn_bwrite },
	{ (struct vnodeop_desc*)NULL, (int(*)())NULL }
};
struct vnodeopv_desc ffs_vnodeop_opv_desc =
	{ &ffs_vnodeop_p, ffs_vnodeop_entries };

int (**ffs_specop_p)();
struct vnodeopv_entry_desc ffs_specop_entries[] = {
	{ &vop_default_desc, vn_default_error },
	{ &vop_lookup_desc, spec_lookup },		/* lookup */
	{ &vop_create_desc, spec_create },		/* create */
	{ &vop_mknod_desc, spec_mknod },		/* mknod */
	{ &vop_open_desc, spec_open },			/* open */
	{ &vop_close_desc, ufsspec_close },		/* close */
	{ &vop_access_desc, ufs_access },		/* access */
	{ &vop_getattr_desc, ufs_getattr },		/* getattr */
	{ &vop_setattr_desc, ufs_setattr },		/* setattr */
	{ &vop_read_desc, ufsspec_read },		/* read */
	{ &vop_write_desc, ufsspec_write },		/* write */
	{ &vop_ioctl_desc, spec_ioctl },		/* ioctl */
	{ &vop_select_desc, spec_select },		/* select */
	{ &vop_mmap_desc, spec_mmap },			/* mmap */
	{ &vop_fsync_desc, ffs_fsync },			/* fsync */
	{ &vop_seek_desc, spec_seek },			/* seek */
	{ &vop_remove_desc, spec_remove },		/* remove */
	{ &vop_link_desc, spec_link },			/* link */
	{ &vop_rename_desc, spec_rename },		/* rename */
	{ &vop_mkdir_desc, spec_mkdir },		/* mkdir */
	{ &vop_rmdir_desc, spec_rmdir },		/* rmdir */
	{ &vop_symlink_desc, spec_symlink },		/* symlink */
	{ &vop_readdir_desc, spec_readdir },		/* readdir */
	{ &vop_readlink_desc, spec_readlink },		/* readlink */
	{ &vop_abortop_desc, spec_abortop },		/* abortop */
	{ &vop_inactive_desc, ufs_inactive },		/* inactive */
	{ &vop_reclaim_desc, ufs_reclaim },		/* reclaim */
	{ &vop_lock_desc, ufs_lock },			/* lock */
	{ &vop_unlock_desc, ufs_unlock },		/* unlock */
	{ &vop_bmap_desc, spec_bmap },			/* bmap */
	{ &vop_strategy_desc, spec_strategy },		/* strategy */
	{ &vop_print_desc, ufs_print },			/* print */
	{ &vop_islocked_desc, ufs_islocked },		/* islocked */
	{ &vop_pathconf_desc, spec_pathconf },		/* pathconf */
	{ &vop_advlock_desc, spec_advlock },		/* advlock */
	{ &vop_blkatoff_desc, spec_blkatoff },		/* blkatoff */
	{ &vop_valloc_desc, spec_valloc },		/* valloc */
	{ &vop_reallocblks_desc, spec_reallocblks },	/* reallocblks */
	{ &vop_vfree_desc, ffs_vfree },			/* vfree */
	{ &vop_truncate_desc, spec_truncate },		/* truncate */
	{ &vop_update_desc, ffs_update },		/* update */
	{ &vop_bwrite_desc, vn_bwrite },
	{ (struct vnodeop_desc*)NULL, (int(*)())NULL }
};
struct vnodeopv_desc ffs_specop_opv_desc =
	{ &ffs_specop_p, ffs_specop_entries };
```

### *vm\_pager* and *vn\_pager* Structures

```c
/* From /sys/vm/vm.h */

struct pager_struct;
typedef struct pager_struct *vm_pager_t;

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
/* From /sys/vm/vnode_pager.h */

/*
 * VNODE pager private data.
 */
struct vnpager {
	int vnp_flags;		/* flags */
	struct vnode *vnp_vp;	/* vnode */
	vm_size_t vnp_size;	/* vnode current size */
};
typedef struct vnpager *vn_pager_t;
```

### *vm\_object* Structures

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

### *vm\_page* Structure

```c
/* From /sys/vm/vm_page.h */

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
### *pv* Structure

```c
/* From /sys/i386/include/pmap.h*/

/*
 * For each vm_page_t, there is a list of all currently valid virtual
 * mappings of that page.  An entry is a pv_entry_t, the list is pv_table.
 */
typedef struct pv_entry {
	struct pv_entry	*pv_next;	/* next pv_entry */
	pmap_t		pv_pmap;	/* pmap where mapping lies */
	vm_offset_t	pv_va;		/* virtual address for mapping */
} *pv_entry_t;
```

## Code Walkthrough

### Pseudo Code Overview

**mmap**: Checks if the address is page aligned and valid for fixed mappings, sets the hint for non-fixed mappings if necessary, checks that the file type is valid, sets the max protections for the mapping, assigns the caddr of the vnode to handle, calls vm\_mmap, sets the addr of the mapping to retval, and returns the error value from vm\)mmap.

1. Enforces mmap argument constraints
2. Checks if the addr for fixed mappings is page aligned and is within VM\_MINUSER\_ADDRESS and VM\_MAXUSER\_ADDRESS. 
3. Sets the hint for non-fixed mappings at the end of the largest possible data segment.
4. Checks if the file we are mapping is either a reg file or a char file, and assigns the MAP\_ANON flag for the /dev/zero file.
5. Uses the file's flags to fill in the mapping's maxprot.
6. Assigns the caddr of the vnode to handle
7. Calls vm\_mmap
8. Assigns retval as the addr of the mapping and returns vm\_mmap's error value.

**vm_mmap**:

1. Checks if the file offset is page aligned.
2. Determines whether we will search for free space in the vm map
3. Uses flags to assign the correct pager type and calls ufs\_getattr to assign the objsize for vnode pagers.
4. Calls vm\_pager\_allocate to create the pager and the object for the mapping.
5. Calls vm\_object\_lookup to verify that the pager has an object, and then calls vm\_object\_deallocate to decrement the object's extra ref.
6. Calls vm\_object\_allocate to create a new object and set the previous object as the backing object.
7. Calls vm\_map\_find to find free space in the va space to insert the mapping.
8. Sets all pages in the mapping to copy-on-write with vm\_object\_pmap\_copy.
9. Prefaults the resident pages with pmap\_object\_init\_pt.
10. Uses vm\_map\_protect to adjust the protections.
11. Calls vm\_map\_inherit to share the mapping with the proc's children.
12. Returns 0 to mmap.

**ufs_getattr**: Uses the inode acquired from VTOI(ap-\>a\_vp) to fill in the vattr structure.

**vm_pager_allocate**: Uses the type arg as an index in the pagertab to call the appropriate pager allocation function and return the pager to vm\)mmap.

**vnode_pager_alloc**:

1. Acquires the lock on the vnode by sleeping on VOLOCK if necessary and setting the VOLOCK bit in vp-\>v\_flag.
2. Sleeps if the OBJ\_DEAD flag is set in vp-\>v\_vmdata-\>fis set in vp-\>v\_vmdata-\>flags  
3. Allocates a pager and vnode pager structure with malloc.
4. Allocates an object using vm\_object\_allocate and sets OBJ\_CANPERSIST.
5. Calls vm\_object\_enter to add the object to the vm\_object\_hashtable.
6. Increments the ref count on the vnode and initializes the pager's data.
7. Sets the VVMIO flag for regular file vnodes.
8. Releases the lock on the vnode by clearing VOLOCK and calling wakeup to wakeup any proc's sleeping for it.
9. Returns the pager structure to vm\_pager\_allocate.

**vm_object_allocate**: Allocates a object structure, passes its pointer \_vm\_object\_allocate to initialize it, and returns the ptr to vnode\_pager\_alloc.

\_**vm_object_allocate**: Initializes the object's memq and reverse\_shadow\_head queue, assigns its size, ref count, flags, pager, shadow object, and offsets, inserts it at the end of the vm\_object\_list, increments the vm\_object\_count, and returns to vm\_object\_allocate.

**vm_object_enter**: Inserts the object/pager/id into the vm\_object\_hashtable.

**vm_object_lookup**: Lookups an object/pager/id in the vm\_object\_hashtable, increments its ref count if its found, and returns its.

**vm_object_deallocate**: Decrements the ref count on the object.

**vm_object_remove**:

**vm_object_terminate**:

\_**vm_object_page_clean**:

**vm_map_find**: Calls vm\_map\_findspace to locate where to place the mapping if findspace is set, and calls vm\_map\_insert to insert the mapping at either the address we found or at \*addr.

1. Assigns \*addr, which is either the fixed-mapping's address or the hint, to start.
2. Sets the priority level to high for the kmem\_map or mb\_map.
3. Calls vm\_map\_findspace to find the free va to insert the mapping and assigns that va to start.
4. Calls vm\_map\_insert to insert the mapping at start.
5. Returns the priority level back to normal for the kmem\_map or mb\_map.
6. Returns the error value of vm\_map\_insert to vm\_mmap.

**vm_map_findspace**:

1. Checks if the starting address is between map-\>min\_offset and map-\>max\_offset.
2. Finds the first free address to start our search at, calling vm\_map\_lookup\_entry if start != map-\>min\_offset and if the first free entry is not the map header.
3. Searches the vm map until it either reaches the last entry or finds an entry that does not overlap with the next entry. 
4. Saves the free entry we just found as a hint for subsequent lookups.
5. Assigns the starting address of the free entry to IN/OUT argument addr.
6. Grows the kernel if we are using the kernel\_map and the new entry exceeds kernel\_vm\_end.
7. Returns 0 for success. 

**vm_map_lookup_entry**:

1. Locks the vm map's hint and assigns the hint to cur.
2. Sets cur to cur-\>next if the hint is &map-\>header (unassigned hint). 
3. Checks if the cur entry precedes the address, setting \(entry = cur and returning TRUE if it does. 
4. Linearly searches from the hint to the end of the map if the address we are searching is >= cur-\>start and searches from the beginning of the map to the hint otherwise.
5. Saves the current entry as the hint When cur-\>start <= address < cur-\>end, assigns \(entry = cur and returns TRUE.
6. If cur-\>end > address, assigns \*entry = cur-\>prev, saves the previous entry as the hint, and returns FALSE.

**vm_map_insert**:

1. Checks if the start address is between map-\>min\_offset and map-\>max\_offset.
2. Checks if the entry we are trying to insert overlaps with an existing entry.
3. Calls vm\_object\_coalesce to combine the objects of the new and previous entry if they are both anonymous mappings with prev-\>end == new-\>start.
4. Calls vm\_map\_entry\_create to create the new entry and assigns its start, end, offset, object, and several other fields such as is\_a\_map and copy\_on\_write.
5. Sets the default inheritance and protections for the main map.
6. Inserts the new entry into the list with vm\_map\_entry\_link.
7. Increments map-\>size with the size of the new entry.
8. Updates the free space hint if it is equal to the previous entry and the previous entry contains the new entry (prev-\>end >= new-\>start).

**vm_map_entry_create**:

**vm_map_entry_link**: Standard linked list code to insert a new entry between two pre-existing entries.

**vm_object_pmap_copy**: Locks the object and sets PG\_COPYONWRITE for every page in the object's pg queue whose offset into the object is between start and end.

**pmap_object_init_pt**: If prefaulting less than 512 pages, maps as many resident pages into the proc's va space as possible, using hash lookups for mappings < 25% object's size and using linear search for mappings > 25% object size.

1. Returns if the pmap doesn't exist or the size of the mapping > 2MiB and the resident pg count > 512.
2. Returns if we cannot lock the object.
3. Updates size to the maximum nb of pages we are able to map if offset + size exceeds object size.
4. If we are prefaulting < 25% of the object's pages, calls vm\_page\_lookup of each pg in the mapping and maps it into the process if it is valid. Otherwise, the object's entire pg queue is searched and pgs are mapped in if they have the appropriate offset.
5. Unlocks the object and returns.

**vm_page_lookup**: Looks up the object/offset pair in the vm\_page\_hash table, checks whether this entry is valid, and returns the vm\_page if its entry and offset matches the one used to find it in the hash table.

**pmap_enter_quick**:

**pmap_remove**:

**get_pv_entry**:

**pmap_use_pt**:

**pmap_pte_vm_page**:

**vm_map_protect**:

**pmap_protect**:

**vm_map_inherit**:

### Documented Code

```c
struct mmap_args {
	caddr_t addr;
	size_t len;
	int prot;
	int flags;
	int fd;
	long pad;
	off_t pos;
};

int
mmap(p, uap, retval)
	struct proc *p;
	register struct mmap_args *uap;
	int *retval;
{
	register struct filedesc *fdp = p->p_fd;
	register struct file *fp;
	struct vnode *vp;
	vm_offset_t addr;
	vm_size_t size;
	vm_prot_t prot, maxprot;
	caddr_t handle;
	int flags, error;

	prot = uap->prot & VM_PROT_ALL;
	flags = uap->flags;
#ifdef DEBUG
	if (mmapdebug & MDB_FOLLOW)
		printf("mmap(%d): addr %x len %x pro %x flg %x fd %d pos %x\n",
		    p->p_pid, uap->addr, uap->len, prot,
		    flags, uap->fd, (vm_offset_t) uap->pos);
#endif
	/*
	 * Address (if FIXED) must be page aligned. Size is implicitly rounded
	 * to a page boundary.
	 */
	addr = (vm_offset_t) uap->addr;

	/* Enforce constraints */
	if (((flags & MAP_FIXED) && (addr & PAGE_MASK)) ||
	    (ssize_t) uap->len < 0 || ((flags & MAP_ANON) && uap->fd != -1))
		return (EINVAL);
	size = (vm_size_t) round_page(uap->len);
	/*
	 * Check for illegal addresses.  Watch out for address wrap... Note
	 * that VM_*_ADDRESS are not constants due to casts (argh).
	 */
	if (flags & MAP_FIXED) {
		if (VM_MAXUSER_ADDRESS > 0 && addr + size > VM_MAXUSER_ADDRESS)
			return (EINVAL);
#ifndef i386
		if (VM_MIN_ADDRESS > 0 && addr < VM_MIN_ADDRESS)
			return (EINVAL);
#endif
		/* Handle address wrap (overflow) */
		if (addr + size < addr)
			return (EINVAL);
	}
	/*
	 * XXX if no hint provided for a non-fixed mapping place it after the
	 * end of the largest possible heap.
	 *
	 * There should really be a pmap call to determine a reasonable location.
	 */
	if (addr == 0 && (flags & MAP_FIXED) == 0)
		addr = round_page(p->p_vmspace->vm_daddr + MAXDSIZ);

	if (flags & MAP_ANON) {
		/*
		 * Mapping blank space is trivial.
		 */
		handle = NULL;			/* Anon mapps have no vnode */
		maxprot = VM_PROT_ALL;	/* All prots by default */
	} else {
		/*
		 * Mapping file, get fp for validation. Obtain vnode and make
		 * sure it is of appropriate type.
		 */
		if (((unsigned) uap->fd) >= fdp->fd_nfiles ||
		    (fp = fdp->fd_ofiles[uap->fd]) == NULL)
			return (EBADF);
		if (fp->f_type != DTYPE_VNODE)	/* DTYPE_VNODE = regular file */
			return (EINVAL);
		vp = (struct vnode *) fp->f_data;
		/* Vnode type must be reg file or char dev */
		if (vp->v_type != VREG && vp->v_type != VCHR)
			return (EINVAL);
		/*
		 * XXX hack to handle use of /dev/zero to map anon memory (ala
		 * SunOS).
		 *
		 * Hence, we use VCHR vnode's for zero filled pages via
		 * /dev/zero.
		 */
		if (vp->v_type == VCHR && iszerodev(vp->v_rdev)) {
			handle = NULL;
			maxprot = VM_PROT_ALL;
			flags |= MAP_ANON;
		} else {
			/*
			 * Ensure that file and memory protections are
			 * compatible.  Note that we only worry about
			 * writability if mapping is shared; in this case,
			 * current and max prot are dictated by the open file.
			 * XXX use the vnode instead?  Problem is: what
			 * credentials do we use for determination? What if
			 * proc does a setuid?
			 *
			 * The "???" below is appropriate since max prot of
			 * exec isn't conservative at all. Why would we ever
			 * mmap something we want to execute? Perhaps shared
			 * libraries?
			 */
			maxprot = VM_PROT_EXECUTE;	/* ??? */
			if (fp->f_flag & FREAD)
				maxprot |= VM_PROT_READ;
			else if (prot & PROT_READ)
				return (EACCES);
			if (flags & MAP_SHARED) {
				if (fp->f_flag & FWRITE)
					maxprot |= VM_PROT_WRITE;
				else if (prot & PROT_WRITE)
					return (EACCES);
			} /* Write perm is default for priv maps */
			  else
				maxprot |= VM_PROT_WRITE;

			/* Assign the vnode ptr to handle */
			handle = (caddr_t) vp;
		}
	}
	error = vm_mmap(&p->p_vmspace->vm_map, &addr, size, prot, maxprot,
	    flags, handle, (vm_offset_t) uap->pos);

	/* Assign addr of the mapping to retval and return */
	if (error == 0)
		*retval = (int) addr;
	return (error);
}
```
