# Walkthrough of FreeBSD 2.1's Kernel Malloc System

## Contents

1. Code Flow
2. Reading Checklist
3. Important Data Structures
4. Code Walkthrough

## Code Flow

```txt
malloc
	kmem_alloc

free
	kmem_free
```

## Reading Checklist

This section lists the relevant functions for the walkthrough by filename,
where each function per filename is listed in the order that it is called.

* The first '+' means that I have read the code or have a general idea of what it does.
* The second '+' means that I have read the code closely and heavily commented it.
* The third '+' means that I have read through the doe again with a focus on the bigger picture.
* The fourth '+' means that I have added it to this document's code walkthrough.

```txt
File: kern_malloc.c
    malloc            ++-+
    free              ++-+

File: vm_kern.c
    kmem_malloc       ++-+
    kmem_free         ++-+
```

## Important Data Structures

### *kmembuckets* Structure

```c
/* From /sys/sys/malloc.h */

/*
 * Set of buckets for each size of memory block that is retained
 */
struct kmembuckets {
	caddr_t kb_next;	/* list of free blocks */
	caddr_t kb_last;	/* last free block */
	long	kb_calls;	/* total calls to allocate this size */
	long	kb_total;	/* total number of blocks allocated */
	long	kb_totalfree;	/* # of free elements in this bucket */
	long	kb_elmpercl;	/* # of elements in this sized allocation */
	long	kb_highwat;	/* high water mark */
	long	kb_couldfree;	/* over high water mark and could free */
};
```

### *kmemusage* Structure

```c
/* From /sys/sys/malloc.h */

/*
 * Array of descriptors that describe the contents of each page
 */
struct kmemusage {
	short ku_indx;		/* bucket index */
	union {
		u_short freecnt;/* for small allocations, free pieces in page */
		u_short pagecnt;/* for large allocations, pages alloced */
	} ku_un;
};
#define ku_freecnt ku_un.freecnt
#define ku_pagecnt ku_un.pagecnt
```

## Code Walkthrough

### *malloc* Code

```c
/* From /sys/sys/param.h */

#define MINBUCKET 4

/* From /sys/sys/malloc.h */

#define	MINALLOCSIZE	(1 << MINBUCKET)
#define BUCKETINDX(size) \
	(size) <= (MINALLOCSIZE * 128) /* <= 2048 */\
		? (size) <= (MINALLOCSIZE * 8) /* <= 128 */\
			? (size) <= (MINALLOCSIZE * 2) /* <= 32 */\
				? (size) <= (MINALLOCSIZE * 1) /* <= 16 */\
					? (MINBUCKET + 0) /* 16 */\
					: (MINBUCKET + 1) /* 32 */\
				: (size) <= (MINALLOCSIZE * 4) /* <= 64 */\
					? (MINBUCKET + 2) /* 64 */\
					: (MINBUCKET + 3) /* 128 */\
			: (size) <= (MINALLOCSIZE * 32) /* <= 512 */\
				? (size) <= (MINALLOCSIZE * 16) /* <= 256 */\
					? (MINBUCKET + 4) /* 256 */\
					: (MINBUCKET + 5) /* 512 */\
				: (size) <= (MINALLOCSIZE * 64) /* <= 1024 */\
					? (MINBUCKET + 6) /* 1024 */\
					: (MINBUCKET + 7) /* 2048 */\
		: (size) <= (MINALLOCSIZE * 2048) /* <= 32768 */\
			? (size) <= (MINALLOCSIZE * 512) /* <= 8192 */\
				? (size) <= (MINALLOCSIZE * 256) /* <= 4096 */\
					? (MINBUCKET + 8) /* 4096 */\
					: (MINBUCKET + 9) /* 8192 */\
				: (size) <= (MINALLOCSIZE * 1024) /* <= 16384 */\
					? (MINBUCKET + 10) /* 16384 */\
					: (MINBUCKET + 11) /* 32768 */\
			: (size) <= (MINALLOCSIZE * 8192) /* <= 131072 */ \
				? (size) <= (MINALLOCSIZE * 4096) /* <= 65536 */\
					? (MINBUCKET + 12) /* 65536 */\
					: (MINBUCKET + 13) /* 131072 */\
				: (size) <= (MINALLOCSIZE * 16384) /* <= 262144 */\
					? (MINBUCKET + 14) /* 262144 */\
					: (MINBUCKET + 15) /* 524288 */

/*
 * Allocate a block of memory
 */
void *
malloc(size, type, flags)
	unsigned long size;
	int type, flags;
{
	register struct kmembuckets *kbp;
	register struct kmemusage *kup;
	register struct freelist *freep;
	long indx, npg, allocsize;
	int s;
	caddr_t va, cp, savedlist;
#ifdef DIAGNOSTIC
	long *end, *lp;
	int copysize;
	char *savedtype;
#endif
#ifdef KMEMSTATS
	register struct kmemstats *ksp = &kmemstats[type];

	if (((unsigned long)type) > M_LAST)
		panic("malloc - bogus type");
#endif
	/*
	 * Obtain the bucket index, where each bucket contains
	 * data on allocations of size 2^(indx).
	 */
	indx = BUCKETINDX(size);
	kbp = &bucket[indx];
	s = splhigh();
#ifdef KMEMSTATS
	while (ksp->ks_memuse >= ksp->ks_limit) {
		if (flags & M_NOWAIT) {
			splx(s);
			return ((void *) NULL);
		}
		if (ksp->ks_limblocks < 65535)
			ksp->ks_limblocks++;
		tsleep((caddr_t)ksp, PSWP+2, memname[type], 0);
	}
	ksp->ks_size |= 1 << indx;
#endif
#ifdef DIAGNOSTIC
	copysize = 1 << indx < MAX_COPY ? 1 << indx : MAX_COPY;
#endif
	/* If no free blocks in bucket, use kmem_malloc */
	if (kbp->kb_next == NULL) {
		kbp->kb_last = NULL;
		/*  size > 8KiB? */
		if (size > MAXALLOCSAVE)
			allocsize = roundup(size, CLBYTES); /* first fit alloc */
		else
			allocsize = 1 << indx;	/* power-of-2 alloc */
		/*
		 * Convert bytes to clicks:
		 * btoc(x) (((unsigned)(x)+(NBPG-1))>>PGSHIFT)
		 *
		 * Convert clicks to bytes:
		 * ctob(x) ((x)<<PGSHIFT)
		 */
		npg = clrnd(btoc(allocsize));

		/* Allocate the memory in the kmem_map submap */
		va = (caddr_t) kmem_malloc(kmem_map, (vm_size_t)ctob(npg), flags);
		if (va == NULL) {
			splx(s);
			return ((void *) NULL);
		}
#ifdef KMEMSTATS
		kbp->kb_total += kbp->kb_elmpercl;
#endif
		/*
		 * Find the kmemusage structure corresponding to the va
		 * and update it.
		 *
		 * btokup(addr)(&kmemusage[((caddr_t)(addr)-kmembase) >> CLSHIFT
		 *                                                      (PGSHIFT)
		 */ 
		kup = btokup(va);
		kup->ku_indx = indx;
				/*    > 8192 */
		if (allocsize > MAXALLOCSAVE) {
			/* Max allocation is 255 MiB */
			if (npg > 65535)
				panic("malloc: allocation too large");
			kup->ku_pagecnt = npg;
#ifdef KMEMSTATS
			ksp->ks_memuse += allocsize;
#endif
			goto out;
		}
#ifdef KMEMSTATS
		kup->ku_freecnt = kbp->kb_elmpercl;
		kbp->kb_totalfree += kbp->kb_elmpercl;
#endif
		/*
		 * Just in case we blocked while allocating memory,
		 * and someone else also allocated memory for this
		 * bucket, don't assume the list is still empty.
		 */
		savedlist = kbp->kb_next;
		kbp->kb_next = cp = va + (npg * NBPG) - allocsize;
		for (;;) {
		/*
		 * struct freelist {
		 * 		caddr_t	next;
		 * };
		 */
			freep = (struct freelist *)cp;
#ifdef DIAGNOSTIC
			/*
			 * Copy in known text to detect modification
			 * after freeing.
			 */
			end = (long *)&cp[copysize];
			for (lp = (long *)cp; lp < end; lp++)
				*lp = WEIRD_ADDR;
			freep->type = M_FREE;
#endif /* DIAGNOSTIC */
			/*
			 * For page aligned allocations we break
			 * the first time we get to this if statement.
			 *
			 * For small power-of-2 allocations, we decrement
			 * and store the caddr of each free block inside
			 * of the free blocks themselves. We break after
			 * writing the value of va inside of the free
			 * block located at va! This is consistent with
			 * large allocations because the value stored at
			 * va for them will be 0 (NULL).
			 */
			if (cp <= va)
				break;
			cp -= allocsize;

			/* Assign the caddr val cp at mem loc cp! */
			freep->next = cp;
		}
		freep->next = savedlist;
		if (kbp->kb_last == NULL)
			kbp->kb_last = (caddr_t)freep;
	}
	/*
	 * We use the last allocsize chunk in the page for
	 * small allocations, NOT the first one!
	 *
	 * Ex. |-----I-----I-----I+++++| -- = free, ++ = reserved
	 *     va              kb_next
	 */
	va = kbp->kb_next;

	/* Assign the next free block (see 2nd blk comment above) */
	kbp->kb_next = ((struct freelist *)va)->next;
#ifdef DIAGNOSTIC
	freep = (struct freelist *)va;
	savedtype = (unsigned)freep->type < M_LAST ?
		memname[freep->type] : "???";
	if (kbp->kb_next &&
	    !kernacc(kbp->kb_next, sizeof(struct freelist), 0)) {
		printf("%s of object %p size %ld %s %s (invalid addr %p)\n",
			"Data modified on freelist: word 2.5", va, size,
			"previous type", savedtype, kbp->kb_next);
		kbp->kb_next = NULL;
	}
#if BYTE_ORDER == BIG_ENDIAN
	freep->type = WEIRD_ADDR >> 16;
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
	freep->type = (short)WEIRD_ADDR;
#endif
	if (((long)(&freep->next)) & 0x2)
		freep->next = (caddr_t)((WEIRD_ADDR >> 16)|(WEIRD_ADDR << 16));
	else
		freep->next = (caddr_t)WEIRD_ADDR;
	end = (long *)&va[copysize];
	for (lp = (long *)va; lp < end; lp++) {
		if (*lp == WEIRD_ADDR)
			continue;
		printf("%s %d of object %p size %ld %s %s (0x%lx != 0x%x)\n",
			"Data modified on freelist: word", lp - (long *)va,
			va, size, "previous type", savedtype, *lp, WEIRD_ADDR);
		break;
	}
	freep->spare0 = 0;
#endif /* DIAGNOSTIC */
#ifdef KMEMSTATS
	kup = btokup(va);
	if (kup->ku_indx != indx)
		panic("malloc: wrong bucket");
	if (kup->ku_freecnt == 0)
		panic("malloc: lost data");
	kup->ku_freecnt--;
	kbp->kb_totalfree--;
	ksp->ks_memuse += 1 << indx;
out:
	kbp->kb_calls++;
	ksp->ks_inuse++;
	ksp->ks_calls++;
	if (ksp->ks_memuse > ksp->ks_maxused)
		ksp->ks_maxused = ksp->ks_memuse;
#else
out:
#endif
	splx(s);
	return ((void *) va);
}

/*
 * Allocate wired-down memory in the kernel's address map for the higher
 * level kernel memory allocator (kern/kern_malloc.c).  We cannot use
 * kmem_alloc() because we may need to allocate memory at interrupt
 * level where we cannot block (canwait == FALSE).
 *
 * This routine has its own private kernel submap (kmem_map) and object
 * (kmem_object).  This, combined with the fact that only malloc uses
 * this routine, ensures that we will never block in map or object waits.
 *
 * Note that this still only works in a uni-processor environment and
 * when called at splhigh().
 *
 * We don't worry about expanding the map (adding entries) since entries
 * for wired maps are statically allocated.
 */
vm_offset_t
kmem_malloc(map, size, waitflag)
	register vm_map_t map;
	register vm_size_t size;
	boolean_t waitflag;
{
	register vm_offset_t offset, i;
	vm_map_entry_t entry;
	vm_offset_t addr;
	vm_page_t m;

	if (map != kmem_map && map != mb_map)
		panic("kmem_malloc: map != {kmem,mb}_map");

	size = round_page(size);
	addr = vm_map_min(map);
	/*
	 * Locate sufficient space in the map.  This will give us the final
	 * virtual address for the new memory, and thus will tell us the
	 * offset within the kernel map.
	 */
	vm_map_lock(map);
	if (vm_map_findspace(map, 0, size, &addr)) {
		vm_map_unlock(map);
		if (map == mb_map) {
			mb_map_full = TRUE;
			log(LOG_ERR, "Out of mbuf clusters - increase maxusers!\n");
			return (0);
		}
		if (waitflag == M_WAITOK)
			panic("kmem_malloc: kmem_map too small");
		return (0);
	}
	offset = addr - vm_map_min(kmem_map);
	vm_object_reference(kmem_object);
	vm_map_insert(map, kmem_object, offset, addr, addr + size);
	/*
	 * If we can wait, just mark the range as wired (will fault pages as
	 * necessary).
	 */
	if (waitflag == M_WAITOK) {
		vm_map_unlock(map);
		(void) vm_map_pageable(map, (vm_offset_t) addr, addr + size,
		    FALSE);
		vm_map_simplify(map, addr);
		return (addr);
	}
	/*
	 * If we cannot wait then we must allocate all memory up front,
	 * pulling it off the active queue to prevent pageout.
	 */
	vm_object_lock(kmem_object);
	for (i = 0; i < size; i += PAGE_SIZE) {
		m = vm_page_alloc(kmem_object, offset + i,
			(waitflag == M_NOWAIT) ? VM_ALLOC_INTERRUPT : VM_ALLOC_SYSTEM);

		/*
		 * Ran out of space, free everything up and return. Don't need
		 * to lock page queues here as we know that the pages we got
		 * aren't on any queues.
		 */
		if (m == NULL) {
			while (i != 0) {
				i -= PAGE_SIZE;
				m = vm_page_lookup(kmem_object, offset + i);
				PAGE_WAKEUP(m);
				vm_page_free(m);
			}
			vm_object_unlock(kmem_object);
			vm_map_delete(map, addr, addr + size);
			vm_map_unlock(map);
			return (0);
		}
#if 0
		vm_page_zero_fill(m);
#endif
		m->flags &= ~PG_BUSY;
		m->valid = VM_PAGE_BITS_ALL;
	}
	vm_object_unlock(kmem_object);

	/*
	 * Mark map entry as non-pageable. Assert: vm_map_insert() will never
	 * be able to extend the previous entry so there will be a new entry
	 * exactly corresponding to this address range and it will have
	 * wired_count == 0.
	 */
	if (!vm_map_lookup_entry(map, addr, &entry) ||
	    entry->start != addr || entry->end != addr + size ||
	    entry->wired_count)
		panic("kmem_malloc: entry not found or misaligned");
	entry->wired_count++;

	/*
	 * Loop thru pages, entering them in the pmap. (We cannot add them to
	 * the wired count without wrapping the vm_page_queue_lock in
	 * splimp...)
	 */
	for (i = 0; i < size; i += PAGE_SIZE) {
		vm_object_lock(kmem_object);
		m = vm_page_lookup(kmem_object, offset + i);
		vm_object_unlock(kmem_object);
		pmap_enter(vm_map_pmap(map), addr + i, VM_PAGE_TO_PHYS(m),
		    VM_PROT_ALL, TRUE);
		m->flags |= PG_MAPPED;
	}
	vm_map_unlock(map);

	vm_map_simplify(map, addr);
	return (addr);
}
```

### *free* Code

```c
/*
 * Free a block of memory allocated by malloc.
 */
void
free(addr, type)
	void *addr;
	int type;
{
	register struct kmembuckets *kbp;
	register struct kmemusage *kup;
	register struct freelist *freep;
	long size;
	int s;
#ifdef DIAGNOSTIC
	caddr_t cp;
	long *end, *lp, alloc, copysize;
#endif
#ifdef KMEMSTATS
	register struct kmemstats *ksp = &kmemstats[type];
#endif

#ifdef DIAGNOSTIC
	if ((char *)addr < kmembase || (char *)addr >= kmemlimit) {
		panic("free: address 0x%x out of range", addr);
	}
	if ((u_long)type > M_LAST) {
		panic("free: type %d out of range", type);
	}
#endif
	/*
	 * Find the kmemusage structure corresponding to addr
	 * and use it to obtain the allocation's kmembucket.
	 *
	 * btokup(addr)(&kmemusage[((caddr_t)(addr)-kmembase) >> CLSHIFT
	 *                                                      (PGSHIFT)
	 */ 
	kup = btokup(addr);
	size = 1 << kup->ku_indx;
	kbp = &bucket[kup->ku_indx];
	s = splhigh();
#ifdef DIAGNOSTIC
	/*
	 * Check for returns of data that do not point to the
	 * beginning of the allocation.
	 */
	if (size > NBPG * CLSIZE)
		alloc = addrmask[BUCKETINDX(NBPG * CLSIZE)];
	else
		alloc = addrmask[kup->ku_indx];
	if (((u_long)addr & alloc) != 0)
		panic("free: unaligned addr 0x%x, size %d, type %s, mask %d",
			addr, size, memname[type], alloc);
#endif /* DIAGNOSTIC */
		/*   > 8192 */
	if (size > MAXALLOCSAVE) {
		kmem_free(kmem_map, (vm_offset_t)addr, ctob(kup->ku_pagecnt));
#ifdef KMEMSTATS
		size = kup->ku_pagecnt << PGSHIFT;
		ksp->ks_memuse -= size;
		kup->ku_indx = 0;
		kup->ku_pagecnt = 0;
		if (ksp->ks_memuse + size >= ksp->ks_limit &&
		    ksp->ks_memuse < ksp->ks_limit)
			wakeup((caddr_t)ksp);
		ksp->ks_inuse--;
		kbp->kb_total -= 1;
#endif
		splx(s);
		return;
	}
	/*
	 * struct freelist {
	 * 		caddr_t	next;
	 * };
	 */
	freep = (struct freelist *)addr;
#ifdef DIAGNOSTIC
	/*
	 * Check for multiple frees. Use a quick check to see if
	 * it looks free before laboriously searching the freelist.
	 */
	if (freep->spare0 == WEIRD_ADDR) {
		for (cp = kbp->kb_next; cp; cp = *(caddr_t *)cp) {
			if (addr != cp)
				continue;
			printf("multiply freed item %p\n", addr);
			panic("free: duplicated free");
		}
	}
	/*
	 * Copy in known text to detect modification after freeing
	 * and to make it look free. Also, save the type being freed
	 * so we can list likely culprit if modification is detected
	 * when the object is reallocated.
	 */
	copysize = size < MAX_COPY ? size : MAX_COPY;
	end = (long *)&((caddr_t)addr)[copysize];
	for (lp = (long *)addr; lp < end; lp++)
		*lp = WEIRD_ADDR;
	freep->type = type;
#endif /* DIAGNOSTIC */
#ifdef KMEMSTATS
	kup->ku_freecnt++;
	if (kup->ku_freecnt >= kbp->kb_elmpercl)
		if (kup->ku_freecnt > kbp->kb_elmpercl)
			panic("free: multiple frees");
		else if (kbp->kb_totalfree > kbp->kb_highwat)
			kbp->kb_couldfree++;
	kbp->kb_totalfree++;
	ksp->ks_memuse -= size;
	if (ksp->ks_memuse + size >= ksp->ks_limit &&
	    ksp->ks_memuse < ksp->ks_limit)
		wakeup((caddr_t)ksp);
	ksp->ks_inuse--;
#endif
	/*
	 * Set freed address to kb_next if no other free blocks,
	 * otherwise assign the caddr of the freed block inside
	 * the last free block.
	 */ 
	if (kbp->kb_next == NULL)
		kbp->kb_next = addr;
	else
		((struct freelist *)kbp->kb_last)->next = addr;

	/* Assign the value 0 in the freed block */
	freep->next = NULL;

	/* Assign the freed block as the last free block */
	kbp->kb_last = addr;
	splx(s);
}

/*
 *	kmem_free:
 *
 *	Release a region of kernel virtual memory allocated
 *	with kmem_alloc, and return the physical pages
 *	associated with that region.
 */
void
kmem_free(map, addr, size)
	vm_map_t map;
	register vm_offset_t addr;
	vm_size_t size;
{
	(void) vm_map_remove(map, trunc_page(addr), round_page(addr + size));
}
```
