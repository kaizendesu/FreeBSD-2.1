# Walkthrough of FreeBSD 2.1's Fork System Call

## Contents

1. Code Flow
2. Reading Checklist
3. Important Data Structures
4. Code Walkthrough

## Code Flow

```txt
fork1
	vm_fork
		cpu_fork
```

## Reading Checklist

This section lists the relevant functions for the walkthrough by filename,
where each function per filename is listed in the order that it is called.

* The first '+' means that I have read the code or have a general idea of what it does.
* The second '+' means that I have read the code closely and heavily commented it.
* The third '+' means that I have read through the doe again with a focus on the bigger picture.
* The fourth '+' means that I have added it to this document's code walkthrough.

```txt
File: kern_fork.c
	fork1				++-+

File: vm_glue.c
	vm_fork				++-+

File: vm_machdep.c
	cpu_fork			++-+

File: swtch.s
	savectx				----
```

## Important Data Structures

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

	int	p_flag;				/* P_* flags. */
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

#define	p_session	p_pgrp->pg_session
#define	p_pgid		p_pgrp->pg_id

/* Status values. */
#define	SIDL	1		/* Process being created by fork. */
#define	SRUN	2		/* Currently runnable. */
#define	SSLEEP	3		/* Sleeping on an address. */
#define	SSTOP	4		/* Process debugging or suspension. */
#define	SZOMB	5		/* Awaiting collection by parent. */
```

### *pgrp* and *session* Structures

```c
/* From /sys/sys/proc.h */

/*
 * One structure allocated per session.
 */
struct	session {
	int	s_count;		/* Ref cnt; pgrps in session. */
	struct	proc *s_leader;		/* Session leader. */
	struct	vnode *s_ttyvp;		/* Vnode of controlling terminal. */
	struct	tty *s_ttyp;		/* Controlling terminal. */
	char	s_login[MAXLOGNAME];	/* Setlogin() name. */
};

/*
 * One structure allocated per process group.
 */
struct	pgrp {
	struct	pgrp *pg_hforw;		/* Forward link in hash bucket. */
	struct	proc *pg_mem;		/* Pointer to pgrp members. */
	struct	session *pg_session;	/* Pointer to session. */
	pid_t	pg_id;			/* Pgrp id. */
	int	pg_jobc;	/* # procs qualifying pgrp for job control */
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
```

### *pcb* Structure

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
```

## Code Walkthrough

```c
static int
fork1(p1, isvfork, retval)
	register struct proc *p1;
	int isvfork, retval[];
{
	register struct proc *p2;
	register uid_t uid;
	struct proc *newproc;
	struct proc **hash;
	int count;
	static int nextpid, pidchecked = 0;

	/*
	 * Although process entries are dynamically created, we still keep
	 * a global limit on the maximum number we will create.  Don't allow
	 * a nonprivileged user to use the last process; don't let root
	 * exceed the limit. The variable nprocs is the current number of
	 * processes, maxproc is the limit.
	 */
	uid = p1->p_cred->p_ruid;
	if ((nprocs >= maxproc - 1 && uid != 0) || nprocs >= maxproc) {
		tablefull("proc");
		return (EAGAIN);
	}
	/*
	 * Increment the nprocs resource before blocking can occur.  There
	 * are hard-limits as to the number of processes that can run.
	 */
	nprocs++;
	/*
	 * Increment the count of procs running with this uid. Don't allow
	 * a nonprivileged user to exceed their current limit.
	 */
	count = chgproccnt(uid, 1);
	if (uid != 0 && count > p1->p_rlimit[RLIMIT_NPROC].rlim_cur) {
		(void)chgproccnt(uid, -1);
		/*
		 * Back out the process count
		 */
		nprocs--;
		return (EAGAIN);
	}

	/* Allocate new proc. */
	MALLOC(newproc, struct proc *, sizeof(struct proc), M_PROC, M_WAITOK);
	/*
	 * Find an unused process ID.  We remember a range of unused IDs
	 * ready to use (from nextpid+1 through pidchecked-1).
	 */
	nextpid++;
retry:
	/*
	 * If the process ID prototype has wrapped around,
	 * restart somewhat above 0, as the low-numbered procs
	 * tend to include daemons that don't exit.
	 *//* PID_MAX = 30000 */
	if (nextpid >= PID_MAX) {
		nextpid = 100;
		pidchecked = 0;
	}
	if (nextpid >= pidchecked) {
		int doingzomb = 0;

		pidchecked = PID_MAX;
		/*
		 * Scan the active and zombie procs to check whether this pid
		 * is in use.  Remember the lowest pid that's greater
		 * than nextpid, so we can avoid checking for a while.
		 *//* allproc is the linked list of all procs */
		p2 = (struct proc *)allproc;
again:
		for (; p2 != NULL; p2 = p2->p_next) {
			while (p2->p_pid == nextpid ||
			    p2->p_pgrp->pg_id == nextpid) {
				nextpid++;
				if (nextpid >= pidchecked)
					goto retry;
			}
			/*
			 * Set pidchecked to the the pid/pg_id that
			 * satisfies nextpid < pid/pg_id < pidchecked.
			 */
			if (p2->p_pid > nextpid && pidchecked > p2->p_pid)
				pidchecked = p2->p_pid;
			if (p2->p_pgrp->pg_id > nextpid &&
			    pidchecked > p2->p_pgrp->pg_id)
				pidchecked = p2->p_pgrp->pg_id;
		}
		if (!doingzomb) {
			doingzomb = 1;
			p2 = zombproc;
			goto again;
		}
	}
	/*
	 * Link onto allproc (this should probably be delayed).
	 * Heavy use of volatile here to prevent the compiler from
	 * rearranging code.  Yes, it *is* terribly ugly, but at least
	 * it works.
	 */
	p2 = newproc;
#define	Vp2 ((volatile struct proc *)p2)
	/* SIDL := proc being created by fork */
	Vp2->p_stat = SIDL;			/* protect against others */
	Vp2->p_pid = nextpid;
	/*
	 * This is really:
	 *	p2->p_next = allproc;
	 *	allproc->p_prev = &p2->p_next; (&allproc)
	 *	p2->p_prev = &allproc;
	 *	allproc = p2;
	 * The assignment via allproc is legal since it is never NULL.
	 */
	*(volatile struct proc **)&Vp2->p_next = allproc;
	*(volatile struct proc ***)&allproc->p_prev =
	    (volatile struct proc **)&Vp2->p_next;
	*(volatile struct proc ***)&Vp2->p_prev = &allproc;
	allproc = Vp2;
#undef Vp2
	p2->p_forw = p2->p_back = NULL;		/* shouldn't be necessary */

	/* Insert on the hash chain. */
	hash = &pidhash[PIDHASH(p2->p_pid)];
	p2->p_hash = *hash;
	*hash = p2;
	/*
	 * Make a proc table entry for the new process.
	 * Start by zeroing the section of proc that is zero-initialized,
	 * then copy the section that is copied directly from the parent.
	 *
	 * #define p_startzero p_ysptr   // younger sibling ptr
	 * #define p_endzero p_startcopy
	 * #define p_startcopy p_sigmask // current signal mask
	 * #define p_endcopy p_thread    // ID for this "thread"
	 */
	bzero(&p2->p_startzero,
	    (unsigned) ((caddr_t)&p2->p_endzero - (caddr_t)&p2->p_startzero));
	bcopy(&p1->p_startcopy, &p2->p_startcopy,
	    (unsigned) ((caddr_t)&p2->p_endcopy - (caddr_t)&p2->p_startcopy));

	/*
	 * XXX: this should be done as part of the startzero above
	 */
	p2->p_vmspace = 0;		/* XXX */
	/*
	 * Duplicate sub-structures as needed.
	 * Increase reference counts on shared objects.
	 * The p_stats and p_sigacts substructs are set in vm_fork.
	 */
	p2->p_flag = P_INMEM;
	if (p1->p_flag & P_PROFIL)
		startprofclock(p2);
	MALLOC(p2->p_cred, struct pcred *, sizeof(struct pcred),
	    M_SUBPROC, M_WAITOK);
	bcopy(p1->p_cred, p2->p_cred, sizeof(*p2->p_cred));
	p2->p_cred->p_refcnt = 1;
	crhold(p1->p_ucred);

	/* bump references to the text vnode (for procfs) */
	p2->p_textvp = p1->p_textvp;
	if (p2->p_textvp)
		VREF(p2->p_textvp);

	p2->p_fd = fdcopy(p1);
	/*
	 * If p_limit is still copy-on-write, bump refcnt,
	 * otherwise get a copy that won't be modified.
	 * (If PL_SHAREMOD is clear, the structure is shared
	 * copy-on-write.)
	 */
	if (p1->p_limit->p_lflags & PL_SHAREMOD)
		p2->p_limit = limcopy(p1->p_limit);
	else {
		p2->p_limit = p1->p_limit;
		p2->p_limit->p_refcnt++;
	}
	/*
	 * Preserve some flags in subprocess.
	 *//* Set User GID */
	p2->p_flag |= p1->p_flag & P_SUGID;
	if (p1->p_session->s_ttyvp != NULL && p1->p_flag & P_CONTROLT)
		p2->p_flag |= P_CONTROLT;
	if (isvfork)
		p2->p_flag |= P_PPWAIT;
	p2->p_pgrpnxt = p1->p_pgrpnxt;
	p1->p_pgrpnxt = p2;
	p2->p_pptr = p1;
	p2->p_osptr = p1->p_cptr;
	if (p1->p_cptr)
		p1->p_cptr->p_ysptr = p2;
	p1->p_cptr = p2;
#ifdef KTRACE
	/*
	 * Copy traceflag and tracefile if enabled.
	 * If not inherited, these were zeroed above.
	 */
	if (p1->p_traceflag&KTRFAC_INHERIT) {
		p2->p_traceflag = p1->p_traceflag;
		if ((p2->p_tracep = p1->p_tracep) != NULL)
			VREF(p2->p_tracep);
	}
#endif
	/*
	 * set priority of child to be that of parent
	 */
	p2->p_estcpu = p1->p_estcpu;
	/*
	 * This begins the section where we must prevent the parent
	 * from being swapped.
	 */
	p1->p_flag |= P_NOSWAP;
	/*
	 * Set return values for child before vm_fork,
	 * so they can be copied to child stack.
	 * We return parent pid, and mark as child in retval[1].
	 * NOTE: the kernel stack may be at a different location in the child
	 * process, and thus addresses of automatic variables (including retval)
	 * may be invalid after vm_fork returns in the child process.
	 */
	retval[0] = p1->p_pid;
	retval[1] = 1;
	if (vm_fork(p1, p2, isvfork)) {
		/*
		 * Child process.  Set start time and get to work.
		 */
		microtime(&runtime);
		p2->p_stats->p_start = runtime;
		p2->p_acflag = AFORK;	/* AFORK := forked but not execed */
		return (0);
	}
	/*
	 * Make child runnable and add to run queue.
	 */
	(void) splhigh();
	p2->p_stat = SRUN;
	setrunqueue(p2);
	(void) spl0();
	/*
	 * Now can be swapped.
	 */
	p1->p_flag &= ~P_NOSWAP;
	/*
	 * Preserve synchronization semantics of vfork.  If waiting for
	 * child to exec or exit, set P_PPWAIT on child, and sleep on our
	 * proc (in case of exit).
	 */
	if (isvfork)
		while (p2->p_flag & P_PPWAIT)
			tsleep(p1, PWAIT, "ppwait", 0);
	/*
	 * Return child pid to parent process,
	 * marking us as parent via retval[1].
	 */
	retval[0] = p2->p_pid;
	retval[1] = 0;
	return (0);
}



```
