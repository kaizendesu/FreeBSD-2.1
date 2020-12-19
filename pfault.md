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
			grow
			vm_map_pmap
			vm_fault
				vm_map_lookup
					vm_map_lookup_entry
					vm_object_shadow
				vm_page_lookup	
				tsleep
					timeout
					unsleep
					mi_switch
					untimeout
				vm_page_unqueue
				vm_page_activate
				vm_page_alloc
					vm_page_remove
					vm_page_insert
				vm_fault_additional_pages
					vm_pager_has_page
					vm_fault_page_lookup
				vm_pager_get_pages
					vm_page_free
				vm_page_zero_fill
					pmap_zero_page
				vm_page_copy
					pmap_copy_page
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

File: vm_machdep.c
	grow						----

File: vm_fault.c
	vm_fault					+---
	vm_fault_additional_pages	----
	vm_fault_page_lookup		----

File: vm_map.c
	vm_map_lookup				++--
	vm_map_lookup_entry			----

File: vm_object.c
	vm_object_shadow			----
	vm_object_collapse			----

File: vm_page.c
	vm_page_lookup				----
	vm_page_alloc				----
	vm_page_remove				----
	vm_page_insert				----
	vm_page_unqueue				----
	vm_page_activate			----
	vm_page_alloc				----
	vm_page_free				----
	vm_page_zero_fill			----
	vm_page_copy				----
	vm_page_wire				----
	vm_page_unwire				----

File: kern_synch.c
	tsleep						----
	unsleep						----
	mi_switch					----

File: kern_clock.c
	timeout						----
	untimeout					----

File: vm_pager.c
	vm_pager_has_page			----
	vm_pager_get_pages			----

File: pmap.c
	pmap_zero_page				----
	pmap_copy_page				----
	pmap_enter					----
	pmap_use_pt					++--
	pmap_unuse_pt				----
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

## Code Walkthrough

### Pseudo Code Descriptions

\_**alltraps**:

**trap**:

**trap\_pfault**:

**grow**:

**vm\_map\_pmap**:

**vm\_fault**:

**vm\_map\_lookup**:

**vm\_map\_lookup\_entry**:

**vm\_object\_shadow**:

**vm\_page\_lookup:

**tsleep**:

**timeout**:

**unsleep**:

**mi\_switch**:

**untimeout**:

**vm\_page\_unqueue**:

**vm\_page\_activate**:

**vm\_page\_alloc**:

**vm\_page\_remove**;

**vm\_page\_insert**:

**vm\_fault\_additional\_pages**:

**vm\_pager\_has\_page**:

**vm\_fault\_page\_lookup**:

**vm\_pager\_get\_pages**:

**vm\_page\_free**:

**vm\_page\_zero\_fill**:

**pmap\_zero\_page**:

**vm\_page\_copy**:

**pmap\_copy\_page**:

**vm\_object\_collapse**:

**pmap\_enter**:

**vm\_page\_wire**:

**vm\_page\_unwire**:

**pmap\_use\_pt**:

**pmap\_unuse\_pt**:

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
