# Walkthrough of FreeBSD 2.1's Kill Signal System Call

## Contents

1. Code Flow
2. Reading Checklist
3. Important Data Structures
4. Code Walkthrough

## Code Flow

```txt
kill
	pfind
	psignal
		sigmask
		sigprop
```

## Reading Checklist

This section lists the relevant functions for the walkthrough by filename,
where each function per filename is listed in the order that it is called.

* The first '+' means that I have read the code or have a general idea of what it does.
* The second '+' means that I have read the code closely and heavily commented it.
* The third '+' means that I have read through the doe again with a focus on the bigger picture.
* The fourth '+' means that I have added it to this document's code walkthrough.

```txt
File: kern_sig.c
	kill			++-+
	psignal			++-+

File: kern_proc.c
	pfind			++--
```

## Important Data Structures

### *sigprop* Array

```c
int sigprop[NSIG + 1] = {
	0,			/* unused */
	SA_KILL,		/* SIGHUP */
	SA_KILL,		/* SIGINT */
	SA_KILL|SA_CORE,	/* SIGQUIT */
	SA_KILL|SA_CORE,	/* SIGILL */
	SA_KILL|SA_CORE,	/* SIGTRAP */
	SA_KILL|SA_CORE,	/* SIGABRT */
	SA_KILL|SA_CORE,	/* SIGEMT */
	SA_KILL|SA_CORE,	/* SIGFPE */
	SA_KILL,		/* SIGKILL */
	SA_KILL|SA_CORE,	/* SIGBUS */
	SA_KILL|SA_CORE,	/* SIGSEGV */
	SA_KILL|SA_CORE,	/* SIGSYS */
	SA_KILL,		/* SIGPIPE */
	SA_KILL,		/* SIGALRM */
	SA_KILL,		/* SIGTERM */
	SA_IGNORE,		/* SIGURG */
	SA_STOP,		/* SIGSTOP */
	SA_STOP|SA_TTYSTOP,	/* SIGTSTP */
	SA_IGNORE|SA_CONT,	/* SIGCONT */
	SA_IGNORE,		/* SIGCHLD */
	SA_STOP|SA_TTYSTOP,	/* SIGTTIN */
	SA_STOP|SA_TTYSTOP,	/* SIGTTOU */
	SA_IGNORE,		/* SIGIO */
	SA_KILL,		/* SIGXCPU */
	SA_KILL,		/* SIGXFSZ */
	SA_KILL,		/* SIGVTALRM */
	SA_KILL,		/* SIGPROF */
	SA_IGNORE,		/* SIGWINCH  */
	SA_IGNORE,		/* SIGINFO */
	SA_KILL,		/* SIGUSR1 */
	SA_KILL,		/* SIGUSR2 */
};

#define	contsigmask	(sigmask(SIGCONT))
#define	stopsigmask	(sigmask(SIGSTOP) | sigmask(SIGTSTP) | \
			    sigmask(SIGTTIN) | sigmask(SIGTTOU))
```

## Code Walkthrough

```c
struct kill_args {
	int	pid;
	int	signum;
};
/* ARGSUSED */
int
kill(cp, uap, retval)
	register struct proc *cp;
	register struct kill_args *uap;
	int *retval;
{
	register struct proc *p;
	register struct pcred *pc = cp->p_cred;

	if ((u_int)uap->signum >= NSIG)
		return (EINVAL);
	if (uap->pid > 0) {
		/* kill single process */
		if ((p = pfind(uap->pid)) == NULL)
			return (ESRCH);
		if (!CANSIGNAL(cp, pc, p, uap->signum))
			return (EPERM);
		if (uap->signum)
			psignal(p, uap->signum);
		return (0);
	}
	switch (uap->pid) {
	case -1:		/* broadcast signal */
		return (killpg1(cp, uap->signum, 0, 1));
	case 0:			/* signal own process group */
		return (killpg1(cp, uap->signum, 0, 0));
	default:		/* negative explicit process group */
		return (killpg1(cp, uap->signum, -uap->pid, 0));
	}
	/* NOTREACHED */
}

/*
 * Send the signal to the process.  If the signal has an action, the action
 * is usually performed by the target process rather than the caller; we add
 * the signal to the set of pending signals for the process.
 *
 * Exceptions:
 *   o When a stop signal is sent to a sleeping process that takes the
 *     default action, the process is stopped without awakening it.
 *   o SIGCONT restarts stopped processes (or puts them back to sleep)
 *     regardless of the signal action (eg, blocked or ignored).
 *
 * Other ignored signals are discarded immediately.
 */
void
psignal(p, signum)
	register struct proc *p;
	register int signum;
{
	register int s, prop;
	register sig_t action;
	int mask;

	if ((u_int)signum >= NSIG || signum == 0)
		panic("psignal signal number");

	/* sigmask(m) (1 << ((m)-1)) */
	mask = sigmask(signum);
	prop = sigprop[signum];
	/*
	 * If proc is traced, always give parent a chance.
	 */
	if (p->p_flag & P_TRACED)
		action = SIG_DFL;	/* action = (void (*)(int))0  */
	else {
		/*
		 * If the signal is being ignored,
		 * then we forget about it immediately.
		 * (Note: we don't set SIGCONT in p_sigignore,
		 * and if it is set to SIG_IGN,
		 * action will be SIG_DFL here.)
		 *//* p_sigignore means ignoring all signals */
		if (p->p_sigignore & mask)
			return;
		if (p->p_sigmask & mask)
			action = SIG_HOLD;	/* action = (void (*)())3 */
		else if (p->p_sigcatch & mask)
			action = SIG_CATCH;	/* action = (void (*)())2 */
		else
			action = SIG_DFL;
	}
	/* Update the nice value for kill signals with default actions */
	if (p->p_nice > NZERO && action == SIG_DFL && (prop & SA_KILL) &&
	    (p->p_flag & P_TRACED) == 0)
		p->p_nice = NZERO;

	/* Clear stop flags for SIGCONT */
	if (prop & SA_CONT)
		p->p_siglist &= ~stopsigmask;

	if (prop & SA_STOP) {
		/*
		 * If sending a tty stop signal to a member of an orphaned
		 * process group, discard the signal here if the action
		 * is default; don't stop the process below if sleeping,
		 * and don't clear any pending SIGCONT.
		 */
		if (prop & SA_TTYSTOP && p->p_pgrp->pg_jobc == 0 &&
		    action == SIG_DFL)
		        return;
		p->p_siglist &= ~contsigmask;
	}
	/* Add the signal to the pending list */
	p->p_siglist |= mask;
	/*
	 * Defer further processing for signals which are held,
	 * except that stopped processes must be continued by SIGCONT.
	 */
	if (action == SIG_HOLD && ((prop & SA_CONT) == 0 || p->p_stat != SSTOP))
		return;
	s = splhigh();
	switch (p->p_stat) {

	case SSLEEP:
		/*
		 * If process is sleeping uninterruptibly
		 * we can't interrupt the sleep... the signal will
		 * be noticed when the process returns through
		 * trap() or syscall().
		 */
		if ((p->p_flag & P_SINTR) == 0)
			goto out;
		/*
		 * Process is sleeping and traced... make it runnable
		 * so it can discover the signal in issignal() and stop
		 * for the parent.
		 */
		if (p->p_flag & P_TRACED)
			goto run;
		/*
		 * If SIGCONT is default (or ignored) and process is
		 * asleep, we are finished; the process should not
		 * be awakened.
		 */
		if ((prop & SA_CONT) && action == SIG_DFL) {
			p->p_siglist &= ~mask;
			goto out;
		}
		/*
		 * When a sleeping process receives a stop
		 * signal, process immediately if possible.
		 * All other (caught or default) signals
		 * cause the process to run.
		 */
		if (prop & SA_STOP) {
			if (action != SIG_DFL)
				goto runfast;
			/*
			 * If a child holding parent blocked,
			 * stopping could cause deadlock.
			 */
			if (p->p_flag & P_PPWAIT)
				goto out;
			p->p_siglist &= ~mask;
			p->p_xstat = signum;
			if ((p->p_pptr->p_flag & P_NOCLDSTOP) == 0)
				psignal(p->p_pptr, SIGCHLD);
			stop(p);
			goto out;
		} else
			goto runfast;
		/*NOTREACHED*/

	case SSTOP:
		/*
		 * If traced process is already stopped,
		 * then no further action is necessary.
		 */
		if (p->p_flag & P_TRACED)
			goto out;
		/*
		 * Kill signal always sets processes running.
		 */
		if (signum == SIGKILL)
			goto runfast;

		if (prop & SA_CONT) {
			/*
			 * If SIGCONT is default (or ignored), we continue the
			 * process but don't leave the signal in p_siglist, as
			 * it has no further action.  If SIGCONT is held, we
			 * continue the process and leave the signal in
			 * p_siglist.  If the process catches SIGCONT, let it
			 * handle the signal itself.  If it isn't waiting on
			 * an event, then it goes back to run state.
			 * Otherwise, process goes back to sleep state.
			 */
			if (action == SIG_DFL)
				p->p_siglist &= ~mask;
			if (action == SIG_CATCH)
				goto runfast;
			if (p->p_wchan == 0)
				goto run;
			p->p_stat = SSLEEP;
			goto out;
		}

		if (prop & SA_STOP) {
			/*
			 * Already stopped, don't need to stop again.
			 * (If we did the shell could get confused.)
			 */
			p->p_siglist &= ~mask;		/* take it away */
			goto out;
		}
		/*
		 * If process is sleeping interruptibly, then simulate a
		 * wakeup so that when it is continued, it will be made
		 * runnable and can look at the signal.  But don't make
		 * the process runnable, leave it stopped.
		 */
		if (p->p_wchan && p->p_flag & P_SINTR)
			unsleep(p);
		goto out;

	default:
		/*
		 * SRUN, SIDL, SZOMB do nothing with the signal,
		 * other than kicking ourselves if we are running.
		 * It will either never be noticed, or noticed very soon.
		 *
		 * #define signotify(p) aston()
		 * #define aston()      setsoftast()
		 * #define setsoftast() (*(unsigned *)&ipending |= SWI_AST_PENDING
		 */
		if (p == curproc)
			signotify(p);
		goto out;
	}
	/*NOTREACHED*/

runfast:
	/*
	 * Raise priority to at least PUSER.
	 */
	if (p->p_priority > PUSER)
		p->p_priority = PUSER;
run:
	setrunnable(p);
out:
	splx(s);
}
```
