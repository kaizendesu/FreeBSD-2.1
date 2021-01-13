# Walkthrough of FreeBSD 2.1's Kernel's VM Initialization Code

## Contents

1. Code Flow
2. Reading Checklist
3. Important Data Structures
4. Code Walkthrough

## Code Flow

```txt
File: locore.s
    btext
        init386
            pmap_bootstrap
        main
            vm_mem_init
                vm_set_page_size
                vm_page_startup
                vm_object_init
                vm_map_startup
                kmem_init
                pmap_init
                vm_pager_init
            kmeminit
            cpu_startup
            vm_init_limits
            vm_pager_bufferinit
```

## Reading Checklist

This section lists the relevant functions for the walkthrough by filename,
where each function per filename is listed in the order that it is called.

* The first '+' means that I have read the code or have a general idea of what it does.
* The second '+' means that I have read the code closely and heavily commented it.
* The third '+' means that I have read through the doe again with a focus on the bigger picture.
* The fourth '+' means that I have added it to this document's code walkthrough.

```txt
File: locore.s
    btext               ++-+

File: machdep.c
    init386             ++-+
    cpu_startup         ++-+

File: vm_init.c
    vm_mem_init         ++-+

File: vm_page.c
    vm_set_page_size    ++--
    vm_page_startup     ++--

File: vm_object.c
    vm_object_init      ++--

File: vm_map.c
    vm_map_startup      ++--

File: vm_kern.c
    kmem_init           ++-+

File: pmap.c
    pmap_bootstrap      ++--
    pmap_init           ++--

File: vm_pager.c
    vm_pager_init       ++--
    vm_pager_bufferinit ++--

File: kern_malloc.c
    kmeminit            ++-+

File: vm_glue.c
    vm_init_limits      ++-+
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

### *user* Structure

```c
/* From /sys/sys/user.h */

/*
 * Per process structure containing data that isn't needed in core
 * when the process isn't running (esp. when swapped out).
 * This structure may or may not be at the same kernel address
 * in all processes.
 */
struct	user {
	struct	pcb u_pcb;

	struct	sigacts u_sigacts;	/* p_sigacts points here (use it!) */
	struct	pstats u_stats;		/* p_stats points here (use it!) */

	/*
	 * Remaining fields only for core dump and/or ptrace--
	 * not valid at other times!
	 */
	struct	kinfo_proc u_kproc;	/* proc + eproc */
	struct	md_coredump u_md;	/* machine dependent glop */
};

/*
 * Redefinitions to make the debuggers happy for now...  This subterfuge
 * brought to you by coredump() and trace_req().  These fields are *only*
 * valid at those times!
 */
#define	U_ar0	u_kproc.kp_proc.p_md.md_regs /* copy of curproc->p_md.md_regs */
#define	U_tsize	u_kproc.kp_eproc.e_vm.vm_tsize
#define	U_dsize	u_kproc.kp_eproc.e_vm.vm_dsize
#define	U_ssize	u_kproc.kp_eproc.e_vm.vm_ssize
#define	U_sig	u_sigacts.ps_sig
#define	U_code	u_sigacts.ps_code

#ifndef KERNEL
#define	u_ar0	U_ar0
#define	u_tsize	U_tsize
#define	u_dsize	U_dsize
#define	u_ssize	U_ssize
#define	u_sig	U_sig
#define	u_code	U_code
#endif /* KERNEL */
```

### Kernel Page Directory and Page Tables

```txt
    Kernel Pg Tbls        
__________________________
|                        |
| KPT 7                  |
|________________________|
|                        |
| KPT 6                  |
|________________________|
|                        |
| KPT 5                  |
|________________________|
|                        |
| KPT 4                  |
|________________________|                                       Kernel Pg Dir
|                        |                                  ________________________
| KPT 3                  |                                  |                      |
|________________________|                                  |        KPT 7         |
|                        |                                  |______________________| 965
| KPT 2                  |                                  |                      |
|________________________|                                  |        KPT 6         |
|                        |                                  |______________________| 964
| KPT 1                  |                                  |                      |
|________________________|                                  |        KPT 5         |
|                        |                                  |______________________| 963 
| proc0 Stack            |                                  |                      |
|________________________| %esi + 3*PGSIZE                  |        KPT 4         |
|                        |                                  |______________________| 962
| UPAGE 2                |                                  |                      |
|________________________| %esi + 2*PGSIZE                  |        KPT 3         |
|                        |                                  |______________________| 961
| UPAGE 1                |                                  |                      |
|________________________| %esi + 1*PGSIZE                  |        KPT 2         |
|                        |                                  |______________________| 960
| Kernel Page Dir        |                                  |                      |
|________________________| %esi                             |        KPT 1         |
|                        | (KERNEND-KERNBASE)/PGSIZE - 1    |______________________| 959
| Kernel Data/BSS (cont) |                                  |                      |
|________________________| 256                              | Recursive KPD Entry  |
|                        | 255                              |______________________| 958
| I/O Memory Map         |                                  |                      |
|________________________| 159                              |    Kernel Stack      |
|                        | 158                              |______________________| 957
| Kernel Data/BSS        |                                  |\\\\\\\\\\\\\\\\\\\\\\|
|________________________| (_etext-KERNBASE)/PGSIZE         |______________________|
|                        | (_etext-KERNBASE)/PGSIZE - 1     |                      |
| Kernel Text            |                                  |        KPT 1         |
|________________________| 0                                |______________________| 0
```

### *vmmeter* Structure

```c
/* From sys/sys/vmmeter.h */

/*
 * System wide statistics counters.
 */
struct vmmeter {
	/*
	 * General system activity.
	 */
	unsigned v_swtch;	/* context switches */
	unsigned v_trap;	/* calls to trap */
	unsigned v_syscall;	/* calls to syscall() */
	unsigned v_intr;	/* device interrupts */
	unsigned v_soft;	/* software interrupts */
	/*
	 * Virtual memory activity.
	 */
	unsigned v_vm_faults;	/* number of address memory faults */
	unsigned v_cow_faults;	/* number of copy-on-writes */
	unsigned v_zfod;	/* pages zero filled on demand */
	unsigned v_swapin;	/* swap pager pageins */
	unsigned v_swapout;	/* swap pager pageouts */
	unsigned v_swappgsin;	/* swap pager pages paged in */
	unsigned v_swappgsout;	/* swap pager pages paged out */
	unsigned v_vnodein;	/* vnode pager pageins */
	unsigned v_vnodeout;	/* vnode pager pageouts */
	unsigned v_vnodepgsin;	/* vnode_pager pages paged in */
	unsigned v_vnodepgsout;	/* vnode pager pages paged out */
	unsigned v_intrans;	/* intransit blocking page faults */
	unsigned v_reactivated;	/* number of pages reactivated from free list */
	unsigned v_pdwakeups;	/* number of times daemon has awaken from sleep */
	unsigned v_pdpages;	/* number of pages analyzed by daemon */
	unsigned v_dfree;	/* pages freed by daemon */
	unsigned v_pfree;	/* pages freed by exiting processes */
	unsigned v_tfree;	/* total pages freed */
	/*
	 * Distribution of page usages.
	 */
	unsigned v_page_size;	/* page size in bytes */
	unsigned v_page_count;	/* total number of pages in system */
	unsigned v_free_reserved; /* number of pages reserved for deadlock */
	unsigned v_free_target;	/* number of pages desired free */
	unsigned v_free_min;	/* minimum number of pages desired free */
	unsigned v_free_count;	/* number of pages free */
	unsigned v_wire_count;	/* number of pages wired down */
	unsigned v_active_count;/* number of pages active */
	unsigned v_inactive_target; /* number of pages desired inactive */
	unsigned v_inactive_count;  /* number of pages inactive */
	unsigned v_cache_count;		/* number of pages on buffer cache queue */
	unsigned v_cache_min;		/* min number of pages desired on cache queue */
	unsigned v_cache_max;		/* max number of pages in cached obj */
	unsigned v_pageout_free_min;	/* min number pages reserved for kernel */
	unsigned v_interrupt_free_min;	/* reserved number of pages for int code */
};
#ifdef KERNEL
struct	vmmeter cnt;
#endif
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
 * Let's assume that the freeBSD kernel is 16MiB in size,
 * which means that 4 KPTs will be dedicated to mapping
 * the kernel image and the remaining 3 will be used for
 * other mappings. Thus, to calculate KERNEND, we simply
 * need to add 16MiB to KERNBASE.
 *
 * 11110000 00000000 00000000 00000000
 * 00000001 00000000 00000000 00000000 +
 * ------------------------------------
 * 11110001 00000000 00000000 00000000  KERNEND
 *
 * The end of the kernel marks the base of the PTD. Hence,
 * KERNEND = PTD.
 *
 * The KPTs are four pages above PTD. Hence,
 *
 * 11110001 00000000 01010000 00000000  KPT
 *
 * There are 7 KPTs, so the end of KPT is given by,
 *
 * 11110001 00000000 11000000 00000000  end of KPT
 *
 * Now that all the addresses have been established, let us visualize
 * them in x386's page format.
 *
 *  pg dir     pg tbl     pg offset
 * 1111000100 0000000000 000000000000  KERNEND
 *
 * 1111000100 0000000101 000000000000  KPT
 * 
 * 1111000100 0000001100 000000000000  end of KPT
 *
 * Now let's look at the code for initializing the pg dir:
 */

/*
 * We want to create 11 ptes with R/W permission, where
 * each pte corresponds to a particular kernel data struct:
 *
 *   1st pte  --> pg dir
 *   2nd pte  --> UPAGE 1
 *   3rd pte  --> UPAGE 2
 *   4th pte  --> proc0 stack
 *   5th pte  --> KPT 1
 *   6th pte  --> KPT 2
 *         ...
 *   11th pte --> KPT 7 
 *
 * Hence, we map 11 ptes to map recursively map the 7 KPTs
 * and to map the other 4 kernel data structures.
 */
	movl	$(1+UPAGES+1+NKPT),%ecx	/* %ecx = 11; number of PTEs */
	movl	%esi,%eax				/* phys address of PTD */
	andl	$PG_FRAME,%eax			/* convert to PFN, should be a NOP */
	orl	$PG_V|PG_KW,%eax			/* valid, kernel read/write */
/*
 * We need to connect the KPTs with the PTD so that the mappings work
 * later on.
 */
	movl	%esi,%ebx	/* calculate pte offset to ptd */

/* 0000000100 0000000000 000000000000  %ebx (KERNEND - KERNBASE) */

	shrl	$PGSHIFT-2,%ebx

/* 0000000000 0000000100 000000000000  %ebx */

	addl	%esi,%ebx	/* address of page directory */

/* 0000000100 0000000100 000000000000  %ebx */

	addl	$((1+UPAGES+1)*NBPG),%ebx	/* offset to kernel page tables */
/*
 * 0000000100 0000000100 000000000000
 *                   100 000000000000 +
 * ------------------------------------
 * 0000000100 0000001000 000000000000  Address of KPT mapping PTD
 *
 * Note: It is helpful to remember that the ONLY difference btw virt and
 * phys addrs in this example is the top four bits are set for vaddrs.
 * Hence, the logic for connecting the KPTs and KPD is clear once you
 * imagine this va passing through the hw addr translation algo.
 */
	fillkpt

/* map I/O memory map */

	movl    _KPTphys-KERNBASE,%ebx		/* base of kernel page tables */
	lea     (0xa0 * PTESIZE)(%ebx),%ebx	/* hardwire ISA hole at KERNBASE + 0xa0000 */
										/* PTESIZE = 4 bytes. Hence, 0xa0 * PTESIZE
										   is equal to the 160th pte */
	movl	$0x100-0xa0,%ecx			/* for this many pte s (96), */
	movl	$(0xa0000|PG_V|PG_KW),%eax	/* valid, kernel read/write, non-cacheable */
	movl	%ebx,_atdevphys-KERNBASE	/* save phys addr of ptes */
	fillkpt

 /* map proc 0's kernel stack into user page table page */

	movl	$UPAGES,%ecx				/* for this many pte s, */
	lea	(1*NBPG)(%esi),%eax				/* physical address in proc 0 */
	lea	(KERNBASE)(%eax),%edx			/* change into virtual addr */
	movl	%edx,_proc0paddr-KERNBASE	/* save VA for proc 0 init */
	orl	$PG_V|PG_KW,%eax				/* valid, kernel read/write */
	lea	((1+UPAGES)*NBPG)(%esi),%ebx	/* addr of stack page table in proc 0 */
	addl	$(KSTKPTEOFF * PTESIZE),%ebx/* offset to kernel stack PTE */
										/* KSTKPTEOFF = 1022 */
	fillkpt

/*
 * Initialize kernel page table directory
 */
	/* install a pde for temporary double map of bottom of VA */
	movl	_KPTphys-KERNBASE,%eax	/* %eax = pa of base of KPT */
	orl     $PG_V|PG_KW,%eax		/* valid, kernel read/write */
	movl	%eax,(%esi)				/* which is where temp maps! */
									/* Remember that %esi is the base
									   of the KPD, so moving %eax there
									   is setting the first pde         */
	/* initialize kernel pde's */
	movl	$(NKPT),%ecx			/* for this many (7) PDEs */
	lea	(KPTDI*PDESIZE)(%esi),%ebx	/* offset of pde for kernel */
									/* KPTDI = 1023 - 63 = 960  */
	fillkpt

	/* install a pde recursively mapping page directory as a page table! */
	movl	%esi,%eax			/* phys address of ptd in proc 0 */
	orl	$PG_V|PG_KW,%eax		/* pde entry is valid */
	movl	%eax,PTDPTDI*PDESIZE(%esi)	/* which is where PTmap maps! */
										/* PTDPTDI = 959 */ 

	/* install a pde to map kernel stack for proc 0 */
	lea	((1+UPAGES)*NBPG)(%esi),%eax	/* physical address of pt in proc 0 */
	orl	$PG_V|PG_KW,%eax				/* pde entry is valid */
	movl	%eax,KSTKPTDI*PDESIZE(%esi)	/* which is where kernel stack maps! */
										/* KSTKPTDI = 958 */

	/* load base of page directory and enable mapping */
	movl	%esi,%eax			/* phys address of ptd in proc 0 */
	movl	%eax,%cr3			/* load ptd addr into mmu */
	movl	%cr0,%eax			/* get control word */
	orl	$CR0_PE|CR0_PG,%eax		/* enable paging */
	movl	%eax,%cr0			/* and let's page NOW! */

	pushl	$begin				/* jump to high mem */
	ret

begin: /* now running relocated at KERNBASE where the system is linked to run */
	movl	_atdevphys,%edx			/* get pte PA */
	subl	_KPTphys,%edx			/* remove base of ptes, now have phys offset */
	shll	$PGSHIFT-2,%edx			/* corresponding to virt offset */
	addl	$KERNBASE,%edx			/* add virtual base */
	movl	%edx,_atdevbase

#include "sc.h"
#include "vt.h"
#if NSC > 0 || NVT > 0
	/* XXX: can't scinit relocate Crtat relative to atdevbase itself? */
	.globl _Crtat				/* XXX - locore should not know about */
	movl	_Crtat,%eax			/* variables of device drivers (pccons)! */
	subl	$(KERNBASE+0xA0000),%eax
	addl	%eax,%edx
	movl	%edx,_Crtat
#endif

	/* set up bootstrap stack - 48 bytes */
	movl	$_kstack+UPAGES*NBPG-4*12,%esp	/* bootstrap stack end location */
											/* _kstack = VM_MAXUSER_ADDRESS
											           = EFBFE000           */
	xorl	%eax,%eax						/* mark end of frames */
	movl	%eax,%ebp						/* %ebp = 0 */
	movl	_proc0paddr,%eax
	movl	%esi,PCB_CR3(%eax)				/* Store PTD into proc0's CR3 */

#ifdef BDE_DEBUGGER
	/* relocate debugger gdt entries */
	movl	$_gdt+8*9,%eax			/* adjust slots 9-17 */
	movl	$9,%ecx
reloc_gdt:
	movb	$KERNBASE>>24,7(%eax)	/* top byte of base addresses, was 0, */
	addl	$8,%eax					/* now KERNBASE>>24 */
	loop	reloc_gdt

	cmpl	$0,_bdb_exists
	je	1f
	int	$3
1:
#endif /* BDE_DEBUGGER */

	/*
	 * Skip over the page tables and the kernel stack
	 */
	lea	((1+UPAGES+1+NKPT)*NBPG)(%esi),%esi

	pushl	%esi				/* value of first for init386(first) */
	call	_init386			/* wire 386 chip for unix operation */
	popl	%esi

	.globl	__ucodesel,__udatasel

	pushl	$0				/* unused */
	pushl	__udatasel			/* ss */
	pushl	$0				/* esp - filled in by execve() */
	pushl	$PSL_USER			/* eflags (IOPL 0, int enab) */
	pushl	__ucodesel			/* cs */
	pushl	$0				/* eip - filled in by execve() */
	subl	$(12*4),%esp			/* space for rest of registers */

	pushl	%esp				/* call main with frame pointer */
	call	_main				/* autoconfiguration, mountroot etc */

	addl	$(13*4),%esp			/* back to a frame we can return with */

	/*
	 * now we've run main() and determined what cpu-type we are, we can
	 * enable write protection and alignment checking on i486 cpus and
	 * above.
	 */
#if defined(I486_CPU) || defined(I586_CPU)
	cmpl    $CPUCLASS_386,_cpu_class
	je	1f
	movl	%cr0,%eax			/* get control word */
	orl	$CR0_WP|CR0_AM,%eax		/* enable i486 features */
	movl	%eax,%cr0			/* and do it */
#endif
	/*
	 * on return from main(), we are process 1
	 * set up address space and stack so that we can 'return' to user mode
	 */
1:
	movl	__ucodesel,%eax
	movl	__udatasel,%ecx

	movl	%cx,%ds
	movl	%cx,%es
	movl	%ax,%fs				/* double map cs to fs */
	movl	%cx,%gs				/* and ds to gs */
	iret						/* goto user! */

void
init386(first)
	int first;
{	/* XXX 48 bytes worth of stack arguments */
	int x;
	unsigned biosbasemem, biosextmem;
	struct gate_descriptor *gdp;
	int gsel_tss;
	/* table descriptors - used to load tables by microp */
	struct region_descriptor r_gdt, r_idt;
	int	pagesinbase, pagesinext;
	int	target_page, pa_indx;

	/*
	 * In sys/kern/init_main.c:
	 *
	 *   struct proc          proc0;
	 *   extern struct user  *proc0paddr;  // globally def in locore.s
	 *
	 * Recall that proc0paddr points to the kernel stack pg in locore.s
	 */
	proc0.p_addr = proc0paddr;
	/*
	 * Initialize the console before we print anything out.
	 */
	cninit ();
	/*
	 * make gdt memory segments, the code segment goes up to end of the
	 * page with etext in it, the data segment goes to the end of
	 * the address space
	 */
	/*
	 * XXX text protection is temporarily (?) disabled.  The limit was
	 * i386_btop(i386_round_page(etext)) - 1.
	 */
	gdt_segs[GCODE_SEL].ssd_limit = i386_btop(0) - 1;
	gdt_segs[GDATA_SEL].ssd_limit = i386_btop(0) - 1;
	for (x = 0; x < NGDT; x++)
		ssdtosd(&gdt_segs[x], &gdt[x].sd);

	/* make ldt memory segments */
	/*
	 * The data segment limit must not cover the user area because we
	 * don't want the user area to be writable in copyout() etc. (page
	 * level protection is lost in kernel mode on 386's).  Also, we
	 * don't want the user area to be writable directly (page level
	 * protection of the user area is not available on 486's with
	 * CR0_WP set, because there is no user-read/kernel-write mode).
	 *
	 * XXX - VM_MAXUSER_ADDRESS is an end address, not a max.  And it
	 * should be spelled ...MAX_USER...
	 */
#define VM_END_USER_RW_ADDRESS	VM_MAXUSER_ADDRESS
	/*
	 * The code segment limit has to cover the user area until we move
	 * the signal trampoline out of the user area.  This is safe because
	 * the code segment cannot be written to directly.
	 */
#define VM_END_USER_R_ADDRESS	(VM_END_USER_RW_ADDRESS + UPAGES * NBPG)
	ldt_segs[LUCODE_SEL].ssd_limit = i386_btop(VM_END_USER_R_ADDRESS) - 1;
	ldt_segs[LUDATA_SEL].ssd_limit = i386_btop(VM_END_USER_RW_ADDRESS) - 1;
	/* Note. eventually want private ldts per process */
	for (x = 0; x < NLDT; x++)
		ssdtosd(&ldt_segs[x], &ldt[x].sd);

	/* exceptions */
	for (x = 0; x < NIDT; x++)
		setidt(x, &IDTVEC(rsvd), SDT_SYS386TGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
	setidt(0, &IDTVEC(div),  SDT_SYS386TGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
	setidt(1, &IDTVEC(dbg),  SDT_SYS386TGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
	setidt(2, &IDTVEC(nmi),  SDT_SYS386TGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
 	setidt(3, &IDTVEC(bpt),  SDT_SYS386TGT, SEL_UPL, GSEL(GCODE_SEL, SEL_KPL));
	setidt(4, &IDTVEC(ofl),  SDT_SYS386TGT, SEL_UPL, GSEL(GCODE_SEL, SEL_KPL));
	setidt(5, &IDTVEC(bnd),  SDT_SYS386TGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
	setidt(6, &IDTVEC(ill),  SDT_SYS386TGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
	setidt(7, &IDTVEC(dna),  SDT_SYS386TGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
	setidt(8, 0,  SDT_SYSTASKGT, SEL_KPL, GSEL(GPANIC_SEL, SEL_KPL));
	setidt(9, &IDTVEC(fpusegm),  SDT_SYS386TGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
	setidt(10, &IDTVEC(tss),  SDT_SYS386TGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
	setidt(11, &IDTVEC(missing),  SDT_SYS386TGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
	setidt(12, &IDTVEC(stk),  SDT_SYS386TGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
	setidt(13, &IDTVEC(prot),  SDT_SYS386TGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
	setidt(14, &IDTVEC(page),  SDT_SYS386TGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
	setidt(15, &IDTVEC(rsvd),  SDT_SYS386TGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
	setidt(16, &IDTVEC(fpu),  SDT_SYS386TGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
	setidt(17, &IDTVEC(align), SDT_SYS386TGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
#if defined(COMPAT_LINUX) || defined(LINUX)
 	setidt(0x80, &IDTVEC(linux_syscall),  SDT_SYS386TGT, SEL_UPL, GSEL(GCODE_SEL, SEL_KPL));
#endif

#include	"isa.h"
#if	NISA >0
	isa_defaultirq();
#endif
	rand_initialize();

	r_gdt.rd_limit = sizeof(gdt) - 1;
	r_gdt.rd_base =  (int) gdt;
	lgdt(&r_gdt);

	r_idt.rd_limit = sizeof(idt) - 1;
	r_idt.rd_base = (int) idt;
	lidt(&r_idt);

	_default_ldt = GSEL(GLDT_SEL, SEL_KPL);
	lldt(_default_ldt);
	currentldt = _default_ldt;

#ifdef DDB
	kdb_init();
	if (boothowto & RB_KDB)
		Debugger("Boot flags requested debugger");
#endif
	/*
	 * Use BIOS values stored in RTC CMOS RAM, since probing
	 * breaks certain 386 AT relics.
	 *
	 * rtcin() is located in locore.s and the RTC_* values are
	 * defined in /usr/src/sys.386bsd/i386/isa/rtc.h (real time clock header).
	 * These values are also found in the IBM Technical Reference PC AT.
	 */

	/* RTC_BASELO = 0x15, RTC_BASEHI = 0x16 
       RTC_EXTLO = 0x17, RTC_EXTHI = 0x18 */
	biosbasemem = rtcin(RTC_BASELO)+ (rtcin(RTC_BASEHI)<<8);
	biosextmem = rtcin(RTC_EXTLO)+ (rtcin(RTC_EXTHI)<<8);
	/*
	 * Print a warning if the official BIOS interface disagrees
	 * with the hackish interface used above.  Eventually only
	 * the official interface should be used.
	 */
	if (bootinfo.bi_memsizes_valid) {
		if (bootinfo.bi_basemem != biosbasemem)
			printf("BIOS basemem (%ldK) != RTC basemem (%dK)\n",
			       bootinfo.bi_basemem, biosbasemem);
		if (bootinfo.bi_extmem != biosextmem)
			printf("BIOS extmem (%ldK) != RTC extmem (%dK)\n",
			       bootinfo.bi_extmem, biosextmem);
	}
	/*
	 * If BIOS tells us that it has more than 640k in the basemem,
	 *	don't believe it - set it to 640k.
	 *
	 *	Conventional memory must be 640k bc memory hole is 384k,
	 *	where 640k + 384k = 1024k = 1MiB.
	 */
	if (biosbasemem > 640)
		biosbasemem = 640;
	/*
	 * Some 386 machines might give us a bogus number for extended
	 *	mem. If this happens, stop now.
	 */
#ifndef LARGEMEM
	if (biosextmem > 65536) {
		panic("extended memory beyond limit of 64MB");
		/* NOTREACHED */
	}
#endif
	/* Convert KiB values to page numbers */
	pagesinbase = biosbasemem * 1024 / NBPG;
	pagesinext = biosextmem * 1024 / NBPG;
	/*
	 * Special hack for chipsets that still remap the 384k hole when
	 *	there's 16MB of memory - this really confuses people that
	 *	are trying to use bus mastering ISA controllers with the
	 *	"16MB limit"; they only have 16MB, but the remapping puts
	 *	them beyond the limit.
	 */
	/*
	 * If extended memory is between 15-16MB (16-17MB phys address range),
	 *	chop it to 15MB.
	 */
	if ((pagesinext > 3840) && (pagesinext < 4096))
		pagesinext = 3840;
	/*
	 * Maxmem isn't the "maximum memory", it's one larger than the
	 * highest page of of the physical address space. It
	 */
	Maxmem = pagesinext + 0x100000/PAGE_SIZE;	/* Maxmem = pagesinext + 256 
												          = pagesinext + 1MiB */

#ifdef MAXMEM
	Maxmem = MAXMEM/4;
#endif
	/*
	 * call pmap initialization to make new kernel address space 
	 *
	 * This function does the following: 
	 *    1. Initializes the static kernel pmap struct 
	 *    2. Maps 8 contiguous page frames following the KPT pages
	 *       as DMA memory. (contiguous va's and pa's)
	 *    3. Maps the 4 subsequent page frames for the Sysmap,
	 *       which is CMAP1, CMAP2, CADDR1, CADDR2, etc.
	 */
	pmap_bootstrap(first, 0);

	/*
	 * Size up each available chunk of physical memory.
	 */

	/*
	 * We currently don't bother testing base memory.
	 * XXX  ...but we probably should.
	 */
	pa_indx = 0;
	badpages = 0;

	/*
	 * phys_avail is a mem map where each entry contains the end address of
	 * a contiguous range of good pages. It has 10 entries, where means
	 * there can only be 9 holes in memory.
	 */
	if (pagesinbase > 1) {
		phys_avail[pa_indx++] = PAGE_SIZE;		/* skip first page of memory */
		phys_avail[pa_indx] = ptoa(pagesinbase);/* memory up to the ISA hole */
		physmem = pagesinbase - 1;
	} else {
		/* point at first chunk end */
		pa_indx++;
	}

	/*
	 * Using the Sysmap ptes, we check the bits of every free page of
	 * memory in the system and identify any bad pages.
	 *
	 * Recall that avail_start is the first page frame following the
	 * DMA pages.
	 */
	for (target_page = avail_start; target_page < ptoa(Maxmem); target_page += PAGE_SIZE) {
		int tmp, page_bad = FALSE;
		/*
		 * map page into kernel: valid, read/write, non-cacheable
		 */
		*(int *)CMAP1 = PG_V | PG_KW | PG_N | target_page;
		pmap_update();

		tmp = *(int *)CADDR1;
		/*
		 * Test for alternating 1's and 0's
		 */
		*(int *)CADDR1 = 0xaaaaaaaa;
		if (*(int *)CADDR1 != 0xaaaaaaaa) {
			page_bad = TRUE;
		}
		/*
		 * Test for alternating 0's and 1's
		 */
		*(int *)CADDR1 = 0x55555555;
		if (*(int *)CADDR1 != 0x55555555) {
			page_bad = TRUE;
		}
		/*
		 * Test for all 1's
		 */
		*(int *)CADDR1 = 0xffffffff;
		if (*(int *)CADDR1 != 0xffffffff) {
			page_bad = TRUE;
		}
		/*
		 * Test for all 0's
		 */
		*(int *)CADDR1 = 0x0;
		if (*(int *)CADDR1 != 0x0) {
			/*
			 * test of page failed
			 */
			page_bad = TRUE;
		}
		/*
		 * Restore original value.
		 */
		*(int *)CADDR1 = tmp;

		/*
		 * Adjust array of valid/good pages.
		 */
		if (page_bad == FALSE) {
			/*
			 * If this good page is a continuation of the
			 * previous set of good pages, then just increase
			 * the end pointer. Otherwise start a new chunk.
			 * Note that "end" points one higher than end,
			 * making the range >= start and < end.
			 */
			if (phys_avail[pa_indx] == target_page) {
				phys_avail[pa_indx] += PAGE_SIZE;
			} else {
				pa_indx++;
				if (pa_indx == PHYS_AVAIL_ARRAY_END) {
					printf("Too many holes in the physical address space, giving up\n");
					pa_indx--;
					break;
				}
				phys_avail[pa_indx++] = target_page;	/* start */
				phys_avail[pa_indx] = target_page + PAGE_SIZE;	/* end */
			}
			physmem++;
		} else {
			badpages++;
			page_bad = FALSE;
		}
	}

	*(int *)CMAP1 = 0;
	pmap_update();

	/*
	 * XXX
	 * The last chunk must contain at least one page plus the message
	 * buffer to avoid complicating other code (message buffer address
	 * calculation, etc.).
	 *
	 * Or in other words, this code ensures that the last entry in the
	 * phys_avail map is large enough so that the end addr of the
	 * penultimate entry + msgbuf struct + PAGE_SIZE does NOT overlap
	 * with the end address of the final entry.
	 */
	while (phys_avail[pa_indx - 1] + PAGE_SIZE +
	    round_page(sizeof(struct msgbuf)) >= phys_avail[pa_indx]) {
		physmem -= atop(phys_avail[pa_indx] - phys_avail[pa_indx - 1]);
		phys_avail[pa_indx--] = 0;
		phys_avail[pa_indx--] = 0;
	}

	Maxmem = atop(phys_avail[pa_indx]);

	/* Trim off space for the message buffer. */
	phys_avail[pa_indx] -= round_page(sizeof(struct msgbuf));

	/* Free memory ends at the msgbuf */
	avail_end = phys_avail[pa_indx];

	/* now running on new page tables, configured,and u/iom is accessible */

	/* make a initial tss so microp can get interrupt stack on syscall! */
	proc0.p_addr->u_pcb.pcb_tss.tss_esp0 = (int) kstack + UPAGES*NBPG;
	proc0.p_addr->u_pcb.pcb_tss.tss_ss0 = GSEL(GDATA_SEL, SEL_KPL) ;
	gsel_tss = GSEL(GPROC0_SEL, SEL_KPL);

	dblfault_tss.tss_esp = dblfault_tss.tss_esp0 = dblfault_tss.tss_esp1 =
	    dblfault_tss.tss_esp2 = (int) &dblfault_stack[sizeof(dblfault_stack)];
	dblfault_tss.tss_ss = dblfault_tss.tss_ss0 = dblfault_tss.tss_ss1 =
	    dblfault_tss.tss_ss2 = GSEL(GDATA_SEL, SEL_KPL);
	dblfault_tss.tss_cr3 = IdlePTD;
	dblfault_tss.tss_eip = (int) dblfault_handler;
	dblfault_tss.tss_eflags = PSL_KERNEL;
	dblfault_tss.tss_ds = dblfault_tss.tss_es = dblfault_tss.tss_fs = dblfault_tss.tss_gs =
		GSEL(GDATA_SEL, SEL_KPL);
	dblfault_tss.tss_cs = GSEL(GCODE_SEL, SEL_KPL);
	dblfault_tss.tss_ldt = GSEL(GLDT_SEL, SEL_KPL);

	((struct i386tss *)gdt_segs[GPROC0_SEL].ssd_base)->tss_ioopt =
		(sizeof(struct i386tss))<<16;

	/* ltr = Load the Task Register */
	ltr(gsel_tss);

	/* make a call gate to reenter kernel with */
	gdp = &ldt[LSYS5CALLS_SEL].gd;

	x = (int) &IDTVEC(syscall);
	gdp->gd_looffset = x++;
	gdp->gd_selector = GSEL(GCODE_SEL,SEL_KPL);
	gdp->gd_stkcpy = 1;
	gdp->gd_type = SDT_SYS386CGT;
	gdp->gd_dpl = SEL_UPL;
	gdp->gd_p = 1;
	gdp->gd_hioffset = ((int) &IDTVEC(syscall)) >>16;

	/* transfer to user mode */

	_ucodesel = LSEL(LUCODE_SEL, SEL_UPL);
	_udatasel = LSEL(LUDATA_SEL, SEL_UPL);

	/* setup proc 0's pcb */
	bcopy(&sigcode, proc0.p_addr->u_pcb.pcb_sigc, szsigcode);
	proc0.p_addr->u_pcb.pcb_flags = 0;
	proc0.p_addr->u_pcb.pcb_ptd = IdlePTD;
}

/*
 *	vm_init initializes the virtual memory system.
 *	This is done only by the first cpu up.
 *
 *	The start and end address of physical memory is passed in.
 */

void
vm_mem_init()
{
	/*
	 * Initializes resident memory structures. From here on, all physical
	 * memory is accounted for, and we use only virtual addresses.
	 */
	vm_set_page_size();

	/*
	 * Allocates:
	 *   1. 2^(log2(total nb of free pgs) + 1) pglists
	 *   2. 10 vm_maps
	 *   3. 128 vm_map_entries
	 *   4. (phys_avail[(nblocks-1)*2+1] - phys_avail[0])/PAGE_SIZE vm_pages
	 */
	virtual_avail = vm_page_startup(avail_start, avail_end, virtual_avail);

	/*
	 * Initialize other VM packages
	 */

	/* Initializes vm_object cache, kernel_object, and kmem_object */
	vm_object_init(virtual_end - VM_MIN_KERNEL_ADDRESS);

	/* Links the kernel vm_maps and vm_map_entries together */
	vm_map_startup();
	/*
	 * Initializes the first static vm_map and vm_map_entry to
	 * represent the kernel image plus all static allocations.
	 */
	kmem_init(virtual_avail, virtual_end);

	/* This function:
	 *   1. Initializes second static vm_map_entry to be ISA device memory 
	 *   2. Intializes third static vm_map_entry to be the idlePTD and all
	 *      addressable KPT pages (not just the 7 static pgs from locore.s)
	 *   3. Allocates the pv_entry array and sets pmap_initialized to TRUE.  
	 */
	pmap_init(avail_start, avail_end);

	/*
	 * Calls the initializing function for the swap, vnode, and device pagers:
	 *   vnode_pager_init: initializes tailq on vnode_pager_list
	 *    swap_pager_init: initializes clean lists & swap alloc constants
	 *     dev_pager_init: initializes dev_pager_list & dev_pager_fakelist
 	 */
	vm_pager_init();
}

/*
 * Initialize the kernel memory allocator
 */
void
kmeminit()
{
	register long indx;
	int npg;

#if	((MAXALLOCSAVE & (MAXALLOCSAVE - 1)) != 0)
		ERROR!_kmeminit:_MAXALLOCSAVE_not_power_of_2
#endif
#if	(MAXALLOCSAVE > MINALLOCSIZE * 32768)
		ERROR!_kmeminit:_MAXALLOCSAVE_too_big
#endif
#if	(MAXALLOCSAVE < CLBYTES)
		ERROR!_kmeminit:_MAXALLOCSAVE_too_small
#endif
	/*
	 * int nmbclusters = 512 + MAXUSERS * 16
	 * #define MCLBYTES (1 << 11)
	 * #define VM_KMEM_SIZE (32 * 1024 * 1024)
	 *
	 * NOTE1: MAXUSERS is a constant that is set when we
	 *        compile the kernel. (-DMAXUSERS=xx)
	 *
	 * NOTE2: nmbclusters = nb of mbuf clusters, where each
	 *       mbuf cluster is 2048 bytes long. Read the text
	 *       on the networking code for more info.
	 *//*   pgs for networking    +  kmem submap */
	npg = (nmbclusters * MCLBYTES + VM_KMEM_SIZE) / PAGE_SIZE;

	/* Alloc the kmemusage array with npg entries in kernel_map */
	kmemusage = (struct kmemusage *) kmem_alloc(kernel_map,
		(vm_size_t)(npg * sizeof(struct kmemusage)));

	/* Create the kmem_map submap for use by kmem_alloc */
	kmem_map = kmem_suballoc(kernel_map, (vm_offset_t *)&kmembase,
		(vm_offset_t *)&kmemlimit, (vm_size_t)(npg * PAGE_SIZE),
		FALSE);
#ifdef KMEMSTATS
	for (indx = 0; indx < MINBUCKET + 16; indx++) {
		if (1 << indx >= CLBYTES)
			bucket[indx].kb_elmpercl = 1;
		else
			bucket[indx].kb_elmpercl = CLBYTES / (1 << indx);
		bucket[indx].kb_highwat = 5 * bucket[indx].kb_elmpercl;
	}
	/*
	 * Limit maximum memory for each type to 60% of malloc area size or
	 * 60% of physical memory, whichever is smaller.
	 */
	for (indx = 0; indx < M_LAST; indx++) {
		kmemstats[indx].ks_limit = min(cnt.v_page_count * PAGE_SIZE,
			(npg * PAGE_SIZE - nmbclusters * MCLBYTES)) * 6 / 10;
	}
#endif
}

void
cpu_startup()
{
	register unsigned i;
	register caddr_t v;
	vm_offset_t maxaddr;
	vm_size_t size = 0;
	int firstaddr, indx;
	vm_offset_t minaddr;

	if (boothowto & RB_VERBOSE)
		bootverbose++;

	/*
	 * Initialize error message buffer (at end of core).
	 */

	/* avail_end was pre-decremented in init_386() to compensate */
	for (i = 0; i < btoc(sizeof (struct msgbuf)); i++)
		pmap_enter(pmap_kernel(), (vm_offset_t)msgbufp,	/* kernel_pmap, va, ... */
			   avail_end + i * NBPG,					/* pa, ... */
			   VM_PROT_ALL, TRUE);						/* prot, wired */
	msgbufmapped = 1;
	/*
	 * Good {morning,afternoon,evening,night}.
	 */
	printf(version);
	startrtclock();
	identifycpu();
	printf("real memory  = %d (%dK bytes)\n", ptoa(Maxmem), ptoa(Maxmem) / 1024);
	/*
	 * Display any holes after the first chunk of extended memory.
	 */
	if (badpages != 0) {
		int indx = 1;
		/*
		 * XXX skip reporting ISA hole & unmanaged kernel memory
		 */
		if (phys_avail[0] == PAGE_SIZE)
			/*
			 * We increment by two because we ended ranges
			 * on memory holes. Hence:
			 *
			 * phys_avail[2n]   = base addr of pg range and/or end of memory hole
			 * phys_avail[2n+1] = end of pg range and/or beg of mem hole
			 */
			indx += 2;

		printf("Physical memory hole(s):\n");
		for (; phys_avail[indx + 1] != 0; indx += 2) {
			int size = phys_avail[indx + 1] - phys_avail[indx];

			printf("0x%08x - 0x%08x, %d bytes (%d pages)\n", phys_avail[indx],
			    phys_avail[indx + 1] - 1, size, size / PAGE_SIZE);
		}
	}

	/*
	 * Quickly wire in netisrs.
	 */
	setup_netisrs(&netisr_set);

/*
#ifdef ISDN
	DONET(isdnintr, NETISR_ISDN);
#endif
*/

	/*
	 * Allocate space for system data structures.
	 * The first available kernel virtual address is in "v".
	 * As pages of kernel virtual memory are allocated, "v" is incremented.
	 * As pages of memory are allocated and cleared,
	 * "firstaddr" is incremented.
	 * An index into the kernel page table corresponding to the
	 * virtual memory address maintained in "v" is kept in "mapaddr".
	 */

	/*
	 * Make two passes.  The first pass calculates how much memory is
	 * needed and allocates it.  The second pass assigns virtual
	 * addresses to the various data structures.
	 */
	firstaddr = 0;
again:
	v = (caddr_t)firstaddr;

#define	valloc(name, type, num) \
	    (name) = (type *)v; v = (caddr_t)((name)+(num))
#define	valloclim(name, type, num, lim) \
	    (name) = (type *)v; v = (caddr_t)((lim) = ((name)+(num)))

	/*
	 * callout = (struct callout *)v; 
	 * v = (caddr_t)(callout+ncallout);
	 */
	valloc(callout, struct callout, ncallout);
#ifdef SYSVSHM
	/*
	 * shmsegs = (struct shmid_ds *)v; 
	 * v = (caddr_t)(shmsegs+shminfo.shmmni);
	 */
	valloc(shmsegs, struct shmid_ds, shminfo.shmmni);
#endif
#ifdef SYSVSEM
	/*
	 * sema = (struct semid_ds *)v; 
	 * v = (caddr_t)(sema+seminfo.semmni);
	 */
	valloc(sema, struct semid_ds, seminfo.semmni);
	/*
	 * sem = (struct sem *)v; 
	 * v = (caddr_t)(sem+seminfo.semmns);
	 */
	valloc(sem, struct sem, seminfo.semmns);
	/* This is pretty disgusting! */
	/*
	 * semu = (struct int *)v; 
	 * v = (caddr_t)(semu+(seminfo.semmnu * seminfo.semusz) / sizeof(int));
	 */
	valloc(semu, int, (seminfo.semmnu * seminfo.semusz) / sizeof(int));
#endif
#ifdef SYSVMSG
	/*
	 * msgpool = (struct char *)v; 
	 * v = (caddr_t)(msgpool+msginfo.msgmax);
	 */
	valloc(msgpool, char, msginfo.msgmax);
	/*
	 * msgmaps = (struct msgmap *)v; 
	 * v = (caddr_t)(msgmaps+msginfo.msgseg);
	 */
	valloc(msgmaps, struct msgmap, msginfo.msgseg);
	/*
	 * msghdrs = (struct msg *)v; 
	 * v = (caddr_t)(msghdrs+msginfo.msgtql);
	 */
	valloc(msghdrs, struct msg, msginfo.msgtql);
	/*
	 * msqids = (struct msqid_ds *)v; 
	 * v = (caddr_t)(msqids+msginfo.msgmni);
	 */
	valloc(msqids, struct msqid_ds, msginfo.msgmni);
#endif

	if (nbuf == 0) {
		nbuf = 30;
		if( physmem > 1024)
			nbuf += min((physmem - 1024) / 12, 1024);
	}
	nswbuf = min(nbuf, 128);

	/*
	 * swbuf = (struct buf *)v; 
	 * v = (caddr_t)(swbuf+nswbuf);
	 */
	valloc(swbuf, struct buf, nswbuf);
	/*
	 * buf = (struct buf *)v; 
	 * v = (caddr_t)(buf+nbuf);
	 */
	valloc(buf, struct buf, nbuf);

#ifdef BOUNCE_BUFFERS
	/*
	 * If there is more than 16MB of memory, allocate some bounce buffers
	 */
	if (Maxmem > 4096) {
		if (bouncepages == 0) {
			bouncepages = 64;
			bouncepages += ((Maxmem - 4096) / 2048) * 32;
		}
		v = (caddr_t)((vm_offset_t)((vm_offset_t)v + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
		valloc(bouncememory, char, bouncepages * PAGE_SIZE);
	}
#endif

	/*
	 * End of first pass, size has been calculated so allocate memory
	 */
	if (firstaddr == 0) {
		size = (vm_size_t)(v - firstaddr);
		/* Allocate space for all the vallocs above with kernel map */ 
		firstaddr = (int)kmem_alloc(kernel_map, round_page(size));
		if (firstaddr == 0)
			panic("startup: no room for tables");
		goto again;
	}

	/*
	 * End of second pass, addresses have been assigned
	 */
	if ((vm_size_t)(v - firstaddr) != size)
		panic("startup: table size inconsistency");

#ifdef BOUNCE_BUFFERS
	clean_map = kmem_suballoc(kernel_map, &clean_sva, &clean_eva,
			(nbuf*MAXBSIZE) + (nswbuf*MAXPHYS) +
				maxbkva + pager_map_size, TRUE);
	io_map = kmem_suballoc(clean_map, &minaddr, &maxaddr, maxbkva, FALSE);
#else
	/* sva = starting virtual addr, eva = ending virtual addr */
	clean_map = kmem_suballoc(kernel_map, &clean_sva, &clean_eva,
			(nbuf*MAXBSIZE) + (nswbuf*MAXPHYS) + pager_map_size, TRUE);
#endif
	buffer_map = kmem_suballoc(clean_map, &buffer_sva, &buffer_eva,
				(nbuf*MAXBSIZE), TRUE);
	pager_map = kmem_suballoc(clean_map, &pager_sva, &pager_eva,
				(nswbuf*MAXPHYS) + pager_map_size, TRUE);
	exec_map = kmem_suballoc(kernel_map, &minaddr, &maxaddr,
				(16*ARG_MAX), TRUE);
	u_map = kmem_suballoc(kernel_map, &minaddr, &maxaddr,
				(maxproc*UPAGES*PAGE_SIZE), FALSE);
	/*
	 * Finally, allocate mbuf pool.  Since mclrefcnt is an off-size
	 * we use the more space efficient malloc in place of kmem_alloc.
	 */
	mclrefcnt = (char *)malloc(nmbclusters+CLBYTES/MCLBYTES,
				   M_MBUF, M_NOWAIT);
	bzero(mclrefcnt, nmbclusters+CLBYTES/MCLBYTES);
	mb_map = kmem_suballoc(kmem_map, (vm_offset_t *)&mbutl, &maxaddr,
			       nmbclusters * MCLBYTES, FALSE);
	/*
	 * Initialize callouts
	 */
	callfree = callout;
	for (i = 1; i < ncallout; i++)
		callout[i-1].c_next = &callout[i];

#if defined(USERCONFIG_BOOT) && defined(USERCONFIG)
	boothowto |= RB_CONFIG;
#endif
        if (boothowto & RB_CONFIG) {
#ifdef USERCONFIG
		userconfig();
		cninit();	/* the preferred console may have changed */
#else
		printf("Sorry! no userconfig in this kernel\n");
#endif
	}

#ifdef BOUNCE_BUFFERS
	/*
	 * init bounce buffers
	 */
	vm_bounce_init();
#endif
	printf("avail memory = %d (%dK bytes)\n", ptoa(cnt.v_free_count),
	    ptoa(cnt.v_free_count) / 1024);

	/*
	 * Set up buffers, so they can be used to read disk labels.
	 */
	bufinit();
	vm_pager_bufferinit();

	/*
	 * Configure the system. (autoconfiguration)
	 */
	configure();

	/*
	 * In verbose mode, print out the BIOS's idea of the disk geometries.
	 */
	if (bootverbose) {
		printf("BIOS Geometries:\n");
		for (i = 0; i < N_BIOS_GEOM; i++) {
			unsigned long bios_geom;
			int max_cylinder, max_head, max_sector;

			bios_geom = bootinfo.bi_bios_geom[i];

			/*
			 * XXX the bootstrap punts a 1200K floppy geometry
			 * when the get-disk-geometry interrupt fails.  Skip
			 * drives that have this geometry.
			 */
			if (bios_geom == 0x4f010f)
				continue;

			printf(" %x:%08x ", i, bios_geom);
			max_cylinder = bios_geom >> 16;
			max_head = (bios_geom >> 8) & 0xff;
			max_sector = bios_geom & 0xff;
			printf(
		"0..%d=%d cylinders, 0..%d=%d heads, 1..%d=%d sectors\n",
			       max_cylinder, max_cylinder + 1,
			       max_head, max_head + 1,
			       max_sector, max_sector);
		}
		printf(" %d accounted for\n", bootinfo.bi_n_bios_used);
	}
}

/*
 * Set default limits for VM system.
 * Called for proc 0, and then inherited by all others.
 */
void
vm_init_limits(p)
	register struct proc *p;
{
	int rss_limit;

	/*
	 * Set up the initial limits on process VM. Set the maximum resident
	 * set size to be half of (reasonably) available memory.  Since this
	 * is a soft limit, it comes into effect only when the system is out
	 * of memory - half of main memory helps to favor smaller processes,
	 * and reduces thrashing of the object cache.
	 */
	p->p_rlimit[RLIMIT_STACK].rlim_cur = DFLSSIZ;
	p->p_rlimit[RLIMIT_STACK].rlim_max = MAXSSIZ;
	p->p_rlimit[RLIMIT_DATA].rlim_cur = DFLDSIZ;
	p->p_rlimit[RLIMIT_DATA].rlim_max = MAXDSIZ;
	/* limit the limit to no less than 2MB */
	rss_limit = max(cnt.v_free_count / 2, 512);
	p->p_rlimit[RLIMIT_RSS].rlim_cur = ptoa(rss_limit);
	p->p_rlimit[RLIMIT_RSS].rlim_max = RLIM_INFINITY;
}

void
vm_pager_bufferinit()
{
	struct buf *bp;
	int i;

	bp = swbuf;
	/*
	 * Now set up swap and physical I/O buffer headers.
	 */
	for (i = 0; i < nswbuf - 1; i++, bp++) {
		TAILQ_INSERT_HEAD(&bswlist, bp, b_freelist);
		bp->b_rcred = bp->b_wcred = NOCRED;
		bp->b_vnbufs.le_next = NOLIST;
	}
	bp->b_rcred = bp->b_wcred = NOCRED;
	bp->b_vnbufs.le_next = NOLIST;
	bp->b_actf = NULL;

	swapbkva = kmem_alloc_pageable(pager_map, nswbuf * MAXPHYS);
	if (!swapbkva)
		panic("Not enough pager_map VM space for physical buffers");
}
```
