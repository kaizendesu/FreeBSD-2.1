# Walkthrough of FreeBSD 2.1's Context Switch Code

## Contents

1. Code Flow
2. Reading Checklist
3. Important Data Structures
4. Code Walkthrough

## Code Flow

```txt
mi_switch
    microtime
    cpu_switch
```

## Reading Checklist

This section lists the relevant functions for the walkthrough by filename,
where each function per filename is listed in the order that it is called.

* The first '+' means that I have read the code or have a general idea of what it does.
* The second '+' means that I have read the code closely and heavily commented it.
* The third '+' means that I have read through the doe again with a focus on the bigger picture.
* The fourth '+' means that I have added it to this document's code walkthrough.

```txt
File: kern_synch.c
    mi_switch            ++-+

File: microtime.s
    microtime            ++-+
File: swtch.s
    cpu_switch           ++-+ 
```

## Important Data Structures

### *timeval* Structure

```c
/* From /sys/sys/time.h */

/*
 * Structure returned by gettimeofday(2) system call,
 * and used in other calls.
 */
struct timeval {
	long	tv_sec;		/* seconds */
	long	tv_usec;	/* and microseconds */
};
```

### *pcb* and *user* Structures

```c
/* From /sys/i386/include/pcb.h */

struct pcb {
	struct	i386tss pcb_tss;
#define	pcb_ksp	pcb_tss.tss_esp0
#define	pcb_ptd	pcb_tss.tss_cr3
#define	pcb_cr3	pcb_ptd
#define	pcb_pc	pcb_tss.tss_eip
#define	pcb_psl	pcb_tss.tss_eflags
#define	pcb_usp	pcb_tss.tss_esp
#define	pcb_fp	pcb_tss.tss_ebp
#ifdef	notyet
	u_char	pcb_iomap[NPORT/sizeof(u_char)]; /* i/o port bitmap */
#endif
	caddr_t	pcb_ldt;		/* per process (user) LDT */
	int	pcb_ldt_len;		/* number of LDT entries */
	struct	save87	pcb_savefpu;	/* floating point state for 287/387 */
	struct	emcsts	pcb_saveemc;	/* Cyrix EMC state */
/*
 * Software pcb (extension)
 */
	int	pcb_flags;
#ifdef notused
#define	FP_WASUSED	0x01	/* process has used fltng pnt hardware */
#define	FP_NEEDSSAVE	0x02	/* ... that needs save on next context switch */
#define	FP_NEEDSRESTORE	0x04	/* ... that needs restore on next DNA fault */
#endif
#define	FP_USESEMC	0x08	/* process uses EMC memory-mapped mode */
#define	FP_SOFTFP	0x20	/* process using software fltng pnt emulator */
	u_char	pcb_inl;	/* intr_nesting_level at context switch */
	caddr_t	pcb_onfault;	/* copyin/out fault recovery */
	long	pcb_sigc[8];	/* XXX signal code trampoline */
	int	pad2;		/* XXX unused - remove it if you change struct */
};

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
```

## Code Walkthrough

```c
ENTRY(microtime)

/* #ifdef I586_CPU */
#if 0
	movl	_pentium_mhz, %ecx
	testl	%ecx, %ecx
	jne	pentium_microtime
#else
	xorl %ecx, %ecx	# clear ecx
#endif
	movb $TIMER_SEL0|TIMER_LATCH, %al	# prepare to latch
										# %al = 0

	cli						# disable interrupts

	outb %al, $TIMER_MODE	# latch timer 0's counter
							# outb $0,0x043
	inb	$TIMER_CNTR0, %al	# read counter value, LSB first
							# inb 0x040,%al
	movb %al, %cl
	inb	$TIMER_CNTR0, %al	# inb 0x040,%al
	movb %al, %ch			# cx = counter value

	# Now check for counter overflow.  This is tricky because the
	# timer chip doesn't let us atomically read the current counter
	# value and the output state (i.e., overflow state).  We have
	# to read the ICU interrupt request register (IRR) to see if the
	# overflow has occured.  Because we lack atomicity, we use
	# the (very accurate) heuristic that we only check for
	# overflow if the value read is close to the interrupt period.
	# E.g., if we just checked the IRR, we might read a non-overflowing
	# value close to 0, experience overflow, then read this overflow
	# from the IRR, and mistakenly add a correction to the "close
	# to zero" value.
	#
	# We compare the counter value to the prepared overflow threshold.
	# If the counter value is less than this, we assume the counter
	# didn't overflow between disabling timer interrupts and latching
	# the counter value above.  For example, we assume that interrupts
	# are enabled when we are called (or were disabled just a few
	# cycles before we are called and that the instructions before the
	# "cli" are fast) and that the "cli" and "outb" instructions take
	# less than 10 timer cycles to execute.  The last assumption is
	# very safe.
	#
	# Otherwise, the counter might have overflowed.  We check for this
	# condition by reading the interrupt request register out of the ICU.
	# If it overflowed, we add in one clock period.
	#
	# The heuristic is "very accurate" because it works 100% if we're
	# called with interrupts enabled.  Otherwise, it might not work.
	# Currently, only siointrts() calls us with interrupts disabled, so
	# the problem can be avoided at some cost to the general case.  The
	# costs are complications in callers to disable interrupts in
	# IO_ICU1 and extra reads of the IRR forced by a conservative
	# overflow threshold.
	#
	# In 2.0, we are called at splhigh() from mi_switch(), so we have
	# to allow for the overflow bit being in ipending instead of in
	# the IRR.  Our caller may have executed many instructions since
	# ipending was set, so the heuristic for the IRR is inappropriate
	# for ipending.  However, we don't need another heuristic, since
	# the "cli" suffices to lock ipending.

	movl _timer0_max_count, %edx	# prepare for 2 uses

	# IRQ0 := 0x0001
	testb $IRQ0, _ipending			# is a soft timer interrupt pending?
	jne overflow					# jmp if _ipending == 0

	# Do we have a possible overflow condition?
	cmpl _timer0_overflow_threshold, %ecx
	jbe	1f				# jmp if counter <= threshold

	inb $IO_ICU1, %al	# read IRR in ICU
						# inb 0x020, %al
	testb $IRQ0, %al	# is a hard timer interrupt pending?
	je 1f				# jmp if %al = 0
overflow:
	subl %edx, %ecx	# some intr pending, count timer down through 0
					# %ecx = counter - _timer0_max_count
1:
	# Subtract counter value from max count since it is a count-down value.
	subl %ecx, %edx	# %edx = _timer0_max_count - counter

	# Adjust for partial ticks.
	addl _timer0_prescaler_count, %edx	# %edx += partial ticks

	# To divide by 1.193200, we multiply by 27465 and shift right by 15.
	#
	# The multiplier was originally calculated to be
	#
	#	2^18 * 1000000 / 1193200 = 219698.
	#
	# The frequency is 1193200 to be compatible with rounding errors in
	# the calculation of the usual maximum count.  2^18 is the largest
	# power of 2 such that multiplying `i' by it doesn't overflow for i
	# in the range of interest ([0, 11932 + 5)).  We adjusted the
	# multiplier a little to minimise the average of
	#
	#	fabs(i / 1.1193200 - ((multiplier * i) >> 18))
	#
	# for i in the range and then removed powers of 2 to speed up the
	# multiplication and to avoid overflow for i outside the range
	# (i may be as high as 2^17 if the timer is programmed to its
	# maximum maximum count).  The absolute error is less than 1 for
	# all i in the range.

#if 0
	imul $27645, %edx				# 25 cycles on a 486
#else
	# Multiply by 27465
	leal (%edx,%edx,2), %eax	# a = 3		2 cycles on a 486
	leal (%edx,%eax,4), %eax	# a = 13	2
	movl %eax, %ecx				# c = 13	1
	shl $5, %eax				# a = 416	2
	addl %ecx, %eax				# a = 429	1
	leal (%edx,%eax,8), %eax	# a = 3433	2
	leal (%edx,%eax,8), %eax	# a = 27465	2 (total 12 cycles)
#endif /* 0 */
	# Divide by 32768
	shr	$15, %eax

common_microtime:
	# _time is a timeval struct
	addl _time+4, %eax	# %eax = usec += time.tv_sec
	movl _time, %edx	# %edx = sec = time.tv_sec

	sti					# enable interrupts

	cmpl $1000000, %eax	# usec valid?
	jb 1f				# jmp if %eax < 1,000,000
	subl $1000000, %eax	# adjust usec
						# %eax -= 1,000,000
	incl %edx			# bump sec
						# %edx += 1
1:
	movl 4(%esp), %ecx	# load timeval pointer arg
	movl %edx, (%ecx)	# tvp->tv_sec = sec
	movl %eax, 4(%ecx)	# tvp->tv_usec = usec

	ret

/*
 * The machine independent parts of mi_switch().
 * Must be called at splstatclock() or higher.
 */
void
mi_switch()
{
	register struct proc *p = curproc;	/* XXX */
	register struct rlimit *rlim;
	register long s, u;
	struct timeval tv;

	/*
	 * Compute the amount of time during which the current
	 * process was running, and add that to its total so far.
	 */
	microtime(&tv);
	/*
	 * Assuming that runtime represents time in kernel:
	 *   u = updated microseconds
	 *   s = updated seconds
	 */
	u = p->p_rtime.tv_usec + (tv.tv_usec - runtime.tv_usec);
	s = p->p_rtime.tv_sec + (tv.tv_sec - runtime.tv_sec);
	
	/* Overflow */
	if (u < 0) {
		u += 1000000;
		s--;
	} /* Second has elapsed */
	  else if (u >= 1000000) {
		u -= 1000000;
		s++;
	}
	/* Update proc time vals */
	p->p_rtime.tv_usec = u;
	p->p_rtime.tv_sec = s;
	/*
	 * Check if the process exceeds its cpu resource allocation.
	 * If over max, kill it.  In any case, if it has run for more
	 * than 10 minutes, reduce priority to give others a chance.
	 */
	if (p->p_stat != SZOMB) {
		rlim = &p->p_rlimit[RLIMIT_CPU];
		if (s >= rlim->rlim_cur) {
			if (s >= rlim->rlim_max)
				killproc(p, "exceeded maximum CPU limit");
			else {
				psignal(p, SIGXCPU);
				if (rlim->rlim_cur < rlim->rlim_max)
					rlim->rlim_cur += 5;
			}
		}
		/* Increase nice value for proc running > 10 mins */
		if (s > 10 * 60 && p->p_ucred->cr_uid && p->p_nice == NZERO) {
			p->p_nice = NZERO + 4;
			resetpriority(p);
		}
	}
	/*
	 * Pick a new current process and record its start time.
	 */
	cnt.v_swtch++;
	cpu_switch(p);
	microtime(&runtime);
}

/*
 * cpu_switch()
 */
ENTRY(cpu_switch)
	/* switch to new process. first, save context as needed */
	movl	_curproc,%ecx		/* %ecx = curproc */

	/* if no process to save, don't bother */
	testl	%ecx,%ecx
	je	sw1						/* jmp if curproc == 0 */

	movl	P_ADDR(%ecx),%ecx	/* %ecx = kva of u_area */

	movl	(%esp),%eax			/* Hardware registers */
	movl	%eax,PCB_EIP(%ecx)	/* set EIP to return addr */
	movl	%ebx,PCB_EBX(%ecx)
	movl	%esp,PCB_ESP(%ecx)
	movl	%ebp,PCB_EBP(%ecx)
	movl	%esi,PCB_ESI(%ecx)
	movl	%edi,PCB_EDI(%ecx)

	movb	_intr_nesting_level,%al
	movb	%al,PCB_INL(%ecx)	/* set interrupt lvl */

#if NNPX > 0
	/* have we used fp, and need a save? */
	mov	_curproc,%eax
	cmp	%eax,_npxproc
	jne	1f
	addl	$PCB_SAVEFPU,%ecx	/* h/w bugs make saving complicated */
	pushl	%ecx
	call	_npxsave			/* do it in a big C function */
	popl	%eax
1:
#endif	/* NNPX > 0 */

	movb	$1,_intr_nesting_level	/* charge Intr, not Sys/Idle */

	movl	$0,_curproc				/* out of process */

	/* save is done, now choose a new process or idle */
sw1:
	cli
sw1a:
/* Check rt procs first */
	movl    _whichrtqs,%edi	/* pick next p. from rtqs */
	testl	%edi,%edi
	jz	nortqr				/* no realtime procs */

/* XXX - bsf is sloow */
	bsfl	%edi,%ebx			/* find a full q */
	jz	nortqr				/* no proc on rt q - try normal ... */

/* XX update whichqs? */
	btrl	%ebx,%edi			/* clear q full status */
	leal	_rtqs(,%ebx,8),%eax		/* select q */
	movl	%eax,%esi

#ifdef        DIAGNOSTIC
	cmpl	P_FORW(%eax),%eax		/* linked to self? (e.g. not on list) */
	je	badsw				/* not possible */
#endif

	movl	P_FORW(%eax),%ecx		/* unlink from front of process q */
	movl	P_FORW(%ecx),%edx
	movl	%edx,P_FORW(%eax)
	movl	P_BACK(%ecx),%eax
	movl	%eax,P_BACK(%edx)

	cmpl	P_FORW(%ecx),%esi		/* q empty */
	je	rt3
	btsl	%ebx,%edi			/* nope, set to indicate not empty */
rt3:
	movl	%edi,_whichrtqs			/* update q status */
	jmp	swtch_com

	/* old sw1a */
/* Normal process priority's */
nortqr:
	movl	_whichqs,%edi
2:
/* XXX - bsf is sloow */
/* bsf = bit scan forward */
	bsfl	%edi,%ebx		/* find a full q */
	jz	idqr				/* if none, idle */

/* XX update whichqs? */
/* btr = bit test reset */
	btrl	%ebx,%edi			/* clear q full status */
	leal	_qs(,%ebx,8),%eax	/* select q */
								/* %eax = _qs + (%ebx*8) 
								       = q hdr          */
	movl	%eax,%esi			/* %esi = q */
#ifdef	DIAGNOSTIC
	cmpl	P_FORW(%eax),%eax 	/* linked to self? (e.g. not on list) */
	je	badsw					/* not possible */
#endif
	movl	P_FORW(%eax),%ecx	/* unlink from front of process q */
								/* %ecx = q->p_forw  (old 1st proc) */
	movl	P_FORW(%ecx),%edx	/* %edx = q->p_forw->p_forw (2nd proc) */
	movl	%edx,P_FORW(%eax)	/* q->p_forw = 2nd proc */
	movl	P_BACK(%ecx),%eax	/* q = (old 1st proc)->p_back */
	movl	%eax,P_BACK(%edx)	/* (2nd proc)->p_back = q */

	cmpl	P_FORW(%ecx),%esi	/* q empty */
								/* (old 1st proc)->p_forw == q ? */
	je	3f						/* jmp if que is empty */
	btsl	%ebx,%edi			/* nope, set to indicate not empty */
3:
	movl	%edi,_whichqs		/* update q status */
	jmp	swtch_com

idqr: /* was sw1a */
	movl    _whichidqs,%edi			/* pick next p. from idqs */

	/* XXX - bsf is sloow */
	bsfl	%edi,%ebx			/* find a full q */
	jz	_idle				/* no proc, idle */

	/* XX update whichqs? */
	btrl	%ebx,%edi			/* clear q full status */
	leal	_idqs(,%ebx,8),%eax		/* select q */
	movl	%eax,%esi

#ifdef        DIAGNOSTIC
	cmpl	P_FORW(%eax),%eax		/* linked to self? (e.g. not on list) */
	je	badsw				/* not possible */
#endif

	movl	P_FORW(%eax),%ecx		/* unlink from front of process q */
	movl	P_FORW(%ecx),%edx
	movl	%edx,P_FORW(%eax)
	movl	P_BACK(%ecx),%eax
	movl	%eax,P_BACK(%edx)

	cmpl	P_FORW(%ecx),%esi		/* q empty */
	je	id3
	btsl	%ebx,%edi			/* nope, set to indicate not empty */
id3:
	movl	%edi,_whichidqs			/* update q status */

swtch_com:
	movl	$0,%eax					/* %eax = 0 */
	movl	%eax,_want_resched		/* _want_resched = 0 */
#ifdef	DIAGNOSTIC
	cmpl	%eax,P_WCHAN(%ecx)
	jne	badsw
	cmpb	$SRUN,P_STAT(%ecx)
	jne	badsw
#endif
	movl	%eax,P_BACK(%ecx) 		/* isolate process to run */
									/* (old 1st proc)->p_back = NULL */
	movl	P_ADDR(%ecx),%edx		/* %edx = new running proc's u_area */
	movl	PCB_CR3(%edx),%ebx		/* %ebx = new running proc's cr3 */

	/* switch address space */
	movl	%ebx,%cr3				/* Update cr3 reg */

	/* restore context */
	movl	PCB_EBX(%edx),%ebx
	movl	PCB_ESP(%edx),%esp
	movl	PCB_EBP(%edx),%ebp
	movl	PCB_ESI(%edx),%esi
	movl	PCB_EDI(%edx),%edi
	movl	PCB_EIP(%edx),%eax		/* %eax = saved eip */
	movl	%eax,(%esp)				/* set return addr */

	movl	%edx,_curpcb
	movl	%ecx,_curproc			/* into next process */

	movb	PCB_INL(%edx),%al		/* saved int nesting lvl */
	movb	%al,_intr_nesting_level	/* update */
#ifdef	USER_LDT
	cmpl	$0, PCB_USERLDT(%edx)
	jnz	1f
	movl	__default_ldt,%eax
	cmpl	_currentldt,%eax
	je	2f
	lldt	__default_ldt
	movl	%eax,_currentldt
	jmp	2f
1:	pushl	%edx
	call	_set_user_ldt
	popl	%edx
2:
#endif
	sti
	ret
```
