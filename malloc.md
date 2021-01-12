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
    free              ----

File: vm_kern.c
    kmem_alloc        ----
    kmem_free         ----
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
		/* struct freelist {
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
			 * For small power-of-2 allocations, we cont
			 * to decrement freep->next to the first empty
			 * block of size allocsize.
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
```
