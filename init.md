# Walkthrough of FreeBSD 2.1's Kernel Initialization Code

## Contents

1. Code Flow
2. Reading Checklist
3. Important Data Structures
4. Code Walkthrough

## Code Flow

```txt
File: locore.s
    btext
```

## Reading Checklist

This section lists the relevant functions for the walkthrough by filename,
where each function per filename is listed in the order that it is called.

* The first '+' means that I have read the code or have a general idea of what it does.
* The second '+' means that I have read the code closely and heavily commented it.
* The third '+' means that I have read through the doe again with a focus on the bigger picture.
* The fourth '+' means that I have added it to this document's code walkthrough.

```txt
```

## Important Data Structures

### *bootinfo* Structure

```c
/* From /sys/i386/include/bootinfo.h */

/*
 * A zero bootinfo field often means that there is no info available.
 * Flags are used to indicate the validity of fields where zero is a
 * normal value.
 */
struct bootinfo {
	unsigned int		bi_version;
	unsigned char		*bi_kernelname;
	struct nfs_diskless	*bi_nfs_diskless;
				/* End of fields that are always present. */
#define	bi_endcommon		bi_n_bios_used
	unsigned int		bi_n_bios_used;
	unsigned long		bi_bios_geom[N_BIOS_GEOM];
	unsigned int		bi_size;
	unsigned char		bi_memsizes_valid;
	unsigned char		bi_pad[3];
	unsigned long		bi_basemem;
	unsigned long		bi_extmem;
	unsigned long		bi_symtab;
	unsigned long		bi_esymtab;
};
```

## Code Walkthrough

```c
/*
 * System Initialization
 */
	.text

/*
 * btext: beginning of text section.
 * Also the entry point (jumped to directly from the boot blocks).
 */
NON_GPROF_ENTRY(btext)
	movw	$0x1234,0x472			/* warm boot */

	/* Set up a real frame, some day we will be doing returns */
	pushl	%ebp
	movl	%esp, %ebp

	/* Don't trust what the BIOS gives for eflags. */
	pushl	$PSL_KERNEL		/* PSL_KERNEL = 0x00000002 */
	popfl

	/* Don't trust what the BIOS gives for %fs and %gs. */
	mov	%ds, %ax
	mov	%ax, %fs
	mov	%ax, %gs			/* Set %gs/%fs to %ds */

	/*
	 * This code is called in different ways depending on what loaded
	 * and started the kernel.  This is used to detect how we get the
	 * arguments from the other code and what we do with them.
	 *
	 * Old disk boot blocks:
	 *	(*btext)(howto, bootdev, cyloffset, esym);
	 *	[return address == 0, and can NOT be returned to]
	 *	[cyloffset was not supported by the FreeBSD boot code
	 *	 and always passed in as 0]
	 *	[esym is also known as total in the boot code, and
	 *	 was never properly supported by the FreeBSD boot code]
	 *
	 * Old diskless netboot code:
	 *	(*btext)(0,0,0,0,&nfsdiskless,0,0,0);
	 *	[return address != 0, and can NOT be returned to]
	 *	If we are being booted by this code it will NOT work,
	 *	so we are just going to halt if we find this case.
	 *
	 * New uniform boot code:
	 *	(*btext)(howto, bootdev, 0, 0, 0, &bootinfo)
	 *	[return address != 0, and can be returned to]
	 *
	 * There may seem to be a lot of wasted arguments in here, but
	 * that is so the newer boot code can still load very old kernels
	 * and old boot code can load new kernels.
	 */

	/*
	 * The old style disk boot blocks fake a frame on the stack and
	 * did an lret to get here.  The frame on the stack has a return
	 * address of 0.
	 */
	cmpl	$0,4(%ebp)
	je	2f				/* olddiskboot: */

	/*
	 * We have some form of return address, so this is either the
	 * old diskless netboot code, or the new uniform code.  That can
	 * be detected by looking at the 5th argument, it if is 0 we
	 * we are being booted by the new unifrom boot code.
	 */
	cmpl	$0,24(%ebp)
	je	1f				/* newboot: */

	/*
	 * Seems we have been loaded by the old diskless boot code, we
	 * don't stand a chance of running as the diskless structure
	 * changed considerably between the two, so just halt.
	 */
	 hlt

	/*
	 * We have been loaded by the new uniform boot code.
	 * Lets check the bootinfo version, and if we do not understand
	 * it we return to the loader with a status of 1 to indicate this error
	 */
1:	/* newboot: */
	movl	28(%ebp),%ebx		/* &bootinfo.version */
	movl	BI_VERSION(%ebx),%eax
	cmpl	$1,%eax				/* We only understand version 1 */
	je	1f
	movl	$1,%eax				/* Return status */
	leave
	ret

1:
	/*
	 * If we have a kernelname copy it in
	 */
	movl	BI_KERNELNAME(%ebx),%esi
	cmpl	$0,%esi
	je	2f							/* No kernelname */
	movl	$MAXPATHLEN,%ecx		/* Brute force!!! */
	lea	_kernelname-KERNBASE,%edi	/* %edi = pa of _kernelname */
	cmpb	$'/',(%esi)				/* Make sure it starts with a slash */
	je	1f
	movb	$'/',(%edi)
	incl	%edi
	decl	%ecx
1:
	cld
	rep
	movsb

2:
	/* 
	 * Determine the size of the boot loader's copy of the bootinfo
	 * struct.  This is impossible to do properly because old versions
	 * of the struct don't contain a size field and there are 2 old
	 * versions with the same version number.
	 */
	movl	$BI_ENDCOMMON,%ecx		/* prepare for sizeless version */
	testl	$RB_BOOTINFO,8(%ebp)	/* bi_size (and bootinfo) valid? */
	je	got_bi_size					/* no, sizeless version */
	movl	BI_SIZE(%ebx),%ecx
got_bi_size:

	/* 
	 * Copy the common part of the bootinfo struct
	 */
	movl	%ebx,%esi					/* %esi = &bootinfo */
	movl	$_bootinfo-KERNBASE,%edi	/* %edi = pa of _bootinfo */
	cmpl	$BOOTINFO_SIZE,%ecx			/* %ecx = sz of bootinfo */
	jbe	got_common_bi_size
	movl	$BOOTINFO_SIZE,%ecx
got_common_bi_size:
	cld
	rep
	movsb								/* Copy bootinfo struct */

#ifdef NFS
	/*
	 * If we have a nfs_diskless structure copy it in
	 */
	movl	BI_NFS_DISKLESS(%ebx),%esi
	cmpl	$0,%esi
	je	2f
	lea	_nfs_diskless-KERNBASE,%edi
	movl	$NFSDISKLESS_SIZE,%ecx
	cld
	rep
	movsb
	lea	_nfs_diskless_valid-KERNBASE,%edi
	movl	$1,(%edi)
#endif

	/*
	 * The old style disk boot.
	 *	(*btext)(howto, bootdev, cyloffset, esym);
	 * Note that the newer boot code just falls into here to pick
	 * up howto and bootdev, cyloffset and esym are no longer used
	 */
2:	/* olddiskboot: */
	movl	8(%ebp),%eax		/* %eax = RB_BOOTINFO|(opts & RBX_MASK) */
	movl	%eax,_boothowto-KERNBASE
	movl	12(%ebp),%eax		/* %eax = MAKEBOOTDEV */
	movl	%eax,_bootdev-KERNBASE

	.
	.
	.

	/*
	 * Finished with old stack; load new %esp now instead of later so
	 * we can trace this code without having to worry about the trace
	 * trap clobbering the memory test or the zeroing of the bss+bootstrap
	 * page tables.
	 *
	 * XXX - wdboot clears the bss after testing that this is safe.
	 * This is too wasteful - memory below 640K is scarce.  The boot
	 * program should check:
	 *	text+data <= &stack_variable - more_space_for_stack
	 *	text+data+bss+pad+space_for_page_tables <= end_of_memory
	 * Oops, the gdt is in the carcass of the boot program so clearing
	 * the rest of memory is still not possible.
	 */
	movl	$tmpstk-KERNBASE,%esp		/* bootstrap stack end location */

/*
 * Virtual address space of kernel:
 *
 *	text | data | bss | [syms] | page dir | proc0 kernel stack | usr stk map | Sysmap
 *      pages:                       1         UPAGES (2)             1        NKPT (7)
 */

/* find end of kernel image */
	movl	$_end-KERNBASE,%ecx		/* %ecx = pa of _end */
	addl	$NBPG-1,%ecx			/* page align up */
	andl	$~(NBPG-1),%ecx
	movl	%ecx,%esi				/* esi = start of free memory (phys addr) */
	movl	%ecx,_KERNend-KERNBASE	/* save end of kernel */

/* clear bss */
	movl	$_edata-KERNBASE,%edi	/* %edi = pa of bss */
	subl	%edi,%ecx				/* get amount to clear */
	xorl	%eax,%eax				/* specify zero fill */
	cld
	rep
	stosb

#ifdef DDB
/* include symbols in "kernel image" if they are loaded */
	movl	_bootinfo+BI_ESYMTAB-KERNBASE,%edi	/* %edi = pa of the end of symtab */
	testl	%edi,%edi
	je	over_symalloc							/* jmp if addr is NULL */
	addl	$NBPG-1,%edi
	andl	$~(NBPG-1),%edi						/* Round up to nearest pg */
	movl	%edi,%esi							/* %esi = rounded pa of esymtab */
	movl	%esi,_KERNend-KERNBASE				/* Incr _KERNend with symtab's len */
	movl	$KERNBASE,%edi
	addl	%edi,_bootinfo+BI_SYMTAB-KERNBASE	/* Virtualize symtab addr */
	addl	%edi,_bootinfo+BI_ESYMTAB-KERNBASE	/* Virtualize esymtab addr */
over_symalloc:
#endif

/*
 * The value in esi is both the end of the kernel bss and a pointer to
 * the kernel page directory, and is used by the rest of locore to build
 * the tables.
 * esi + 1(page dir) + 2(UPAGES) + 1(p0stack) + NKPT(number of kernel
 * page table pages) is then passed on the stack to init386(first) as
 * the value first. esi should ALWAYS be page aligned!!
 */
	movl	%esi,%ecx			/* Get current first availiable address */
								/* %ecx = %esi; base of pg dir */

/* clear pagetables, page directory, stack, etc... */
	movl	%esi,%edi						/* base (page directory) */
	movl	$((1+UPAGES+1+NKPT)*NBPG),%ecx	/* amount to clear */
	xorl	%eax,%eax						/* specify zero fill */
	cld
	rep
	stosb									/* Clear 11 pgs of mem */

/* physical address of Idle proc/kernel page directory */
	movl	%esi,_IdlePTD-KERNBASE

/*
 * fillkpt
 *	eax = (page frame address | control | status) == pte
 *	ebx = address of page table
 *	ecx = how many pages to map
 */
#define	fillkpt		\
1:	movl	%eax,(%ebx)	; \
	addl	$NBPG,%eax	; /* increment physical address */ \
	addl	$4,%ebx		; /* next pte */ \
	loop	1b		;

/*
 * Map Kernel
 *
 * First step - build page tables
 */
#if defined (KGDB) || defined (BDE_DEBUGGER)
	movl	_KERNend-KERNBASE,%ecx	/* this much memory, */
	shrl	$PGSHIFT,%ecx			/* for this many PTEs */
#ifdef BDE_DEBUGGER
	cmpl	$0xa0,%ecx			/* XXX - cover debugger pages */
	jae	1f
	movl	$0xa0,%ecx
1:
#endif /* BDE_DEBUGGER */
	movl	$PG_V|PG_KW,%eax			/* kernel R/W, valid, pg frame 0 */
	lea	((1+UPAGES+1)*NBPG)(%esi),%ebx	/* phys addr of kernel PT base */
	movl	%ebx,_KPTphys-KERNBASE		/* save pa in global */
	fillkpt

#else /* !KGDB && !BDE_DEBUGGER */
	/* write protect kernel text (doesn't do a thing for 386's - only 486's) */
	movl	$_etext-KERNBASE,%ecx	/* get size of text */
	addl	$NBPG-1,%ecx			/* round up to page */
	shrl	$PGSHIFT,%ecx			/* for this many PTEs */
	movl	$PG_V|PG_KR,%eax		/* specify read only */
#if 0
/*	movl	$_etext,%ecx			// get size of text
	subl	$_btext,%ecx
	addl	$NBPG-1,%ecx			// round up to page
	shrl	$PGSHIFT,%ecx			// for this many PTEs
	movl	$_btext-KERNBASE,%eax	// get offset to physical memory
	orl	$PG_V|PG_KR,%eax			// specify read only
*/
#endif
	lea	((1+UPAGES+1)*NBPG)(%esi),%ebx	/* phys addr of kernel PT base */
	movl	%ebx,_KPTphys-KERNBASE		/* save pa in global */
	fillkpt

	/* data and bss are r/w */
	andl	$PG_FRAME,%eax			/* strip to just addr of bss */
									/* should be addr of data, not bss */
	movl	_KERNend-KERNBASE,%ecx	/* calculate size... */
	subl	%eax,%ecx				/* ... of data segments */
	shrl	$PGSHIFT,%ecx
	orl	$PG_V|PG_KW,%eax		/* valid, kernel read/write */
	fillkpt
#endif /* KGDB || BDE_DEBUGGER */

/* now initialize the page dir, upages, p0stack PT, and page tables */

/*
 * 11110000 00000000 00000000 00000000	KERNBASE
 *
 * The kernel has 7 page table pages, which means it is 28MiB in size.
 * Hence, we need to add 28 MiB to KERNBASE to determine the va of
 * KERNEND.
 *
 * 11110000 00000000 00000000 00000000
 * 00000001 11000000 00000000 00000000 +
 * ------------------------------------
 * 11110001 11000000 00000000 00000000  KERNEND
 *
 * The end of the kernel marks the base of the PTD. Hence,
 * KERNEND = PTD.
 *
 * The KPTs are four pages above PTD. Hence,
 *
 * 11110001 11000000 01010000 00000000  KPT
 *
 * There are 7 KPTs, so the end of KPT is given by,
 *
 * 11110001 11000000 11000000 00000000  end of KPT
 *
 * Now that all the addresses have been established, let us visualize
 * them in x386's page format.
 *
 *  pg dir     pg tbl     pg offset
 * 1111000111 0000000000 000000000000  KERNEND
 *
 * 1111000111 0000000101 000000000000  KPT
 * 
 * 1111000111 0000001100 000000000000  end of KPT
 *
 * Now let's look at the code for initializing the pg dir:
 */

/* We want to create 11 pdes with R/W permission. */
	movl	$(1+UPAGES+1+NKPT),%ecx	/* %ecx = 11; number of PTEs */
	movl	%esi,%eax				/* phys address of PTD */
	andl	$PG_FRAME,%eax			/* convert to PFN, should be a NOP */
	orl	$PG_V|PG_KW,%eax			/* valid, kernel read/write */
/*
 * We need to connect the KPTs with the PTD so that the mappings work
 * later on.
 */
	movl	%esi,%ebx	/* calculate pte offset to ptd */

/* 0000000111 0000000000 000000000000  %ebx (KERNEND - KERNBASE) */

	shrl	$PGSHIFT-2,%ebx

/* 0000000000 0000000111 000000000000  %ebx */

	addl	%esi,%ebx	/* address of page directory */

/* 0000000111 0000000111 000000000000  %ebx */

	addl	$((1+UPAGES+1)*NBPG),%ebx	/* offset to kernel page tables */
/*
 * 0000000111 0000000111 000000000000
 *                   100 000000000000 +
 * ------------------------------------
 * 0000000111 0000001011 000000000000  Address of KPT mapping PTD
 *
 * Note: It is helpful to remember that the ONLY difference btw virt and
 * phys addrs in this example is the top four bits are set for vaddrs.
 * Hence, the logic for connecting the KPTs and KPD is clear once you
 * imagine this va passing through the hw addr translation algo.
 */
	fillkpt
```
