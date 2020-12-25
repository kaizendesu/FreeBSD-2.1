# Walkthrough of FreeBSD 2.1's Execve System Call

## Contents

1. Code Flow
2. Reading Checklist
3. Important Data Structures
4. Code Walkthrough

## Code Flow

```txt
execve
	exec_aout_imgact
		exec_extract_strings
		exec_new_vmspace
	exec_copyout_strings
		suword
	fdcloseexec
	setregs
```

## Reading Checklist

This section lists the relevant functions for the walkthrough by filename,
where each function per filename is listed in the order that it is called.

* The first '+' means that I have read the code or have a general idea of what it does.
* The second '+' means that I have read the code closely and heavily commented it.
* The third '+' means that I have read through the doe again with a focus on the bigger picture.
* The fourth '+' means that I have added it to this document's code walkthrough.

```txt
File: kern_exec.c
	execve					++-+
	exec_extract_strings	++--
	exec_new_vmspace		----
	exec_copyout_strings	----

File: imgact_aout.c
	exec_aout_imgact		++-+

File: support.s
	suword					----

File: kern_descrip.c
	fdcloseexec				----

File: machdep.c
	setregs					----
```

## Important Data Structures

### *image_params* Structure

```c
/* From /sys/sys/imgact.h */

struct image_params {
	struct proc *proc;	/* our process struct */
	struct execve_args *uap; /* syscall arguments */
	struct vnode *vnodep;	/* pointer to vnode of file to exec */
	struct vattr *attr;	/* attributes of file */
	const char *image_header; /* head of file to exec */
	char *stringbase;	/* base address of tmp string storage */
	char *stringp;		/* current 'end' pointer of tmp strings */
	int stringspace;	/* space left in tmp string storage area */
	int argc, envc;		/* count of argument and environment strings */
	unsigned long entry_addr; /* entry address of target executable */
	char vmspace_destroyed;	/* flag - we've blown away original vm space */
	char interpreted;	/* flag - this executable is interpreted */
	char interpreter_name[64]; /* name of the interpreter */
};
```

### *exec* Structure

```c
/*
 * Header prepended to each a.out file.
 * only manipulate the a_midmag field via the
 * N_SETMAGIC/N_GET{MAGIC,MID,FLAG} macros in a.out.h
 */
struct exec {
     unsigned long	a_midmag;	/* flags<<26 | mid<<16 | magic */
     unsigned long	a_text;		/* text segment size */
     unsigned long	a_data;		/* initialized data size */
     unsigned long	a_bss;		/* uninitialized data size */
     unsigned long	a_syms;		/* symbol table size */
     unsigned long	a_entry;	/* entry point */
     unsigned long	a_trsize;	/* text relocation size */
     unsigned long	a_drsize;	/* data relocation size */
};
#define a_magic a_midmag /* XXX Hack to work with current kern_execve.c */

/* a_magic */
#define	OMAGIC		0407	/* old impure format */
#define	NMAGIC		0410	/* read-only text */
#define	ZMAGIC		0413	/* demand load format */
#define QMAGIC          0314    /* "compact" demand load format */

/* a_mid */
#define	MID_ZERO	0	/* unknown - implementation dependent */
#define	MID_SUN010	1	/* sun 68010/68020 binary */
#define	MID_SUN020	2	/* sun 68020-only binary */
#define MID_I386	134	/* i386 BSD binary */
#define MID_SPARC	138	/* sparc */
#define	MID_HP200	200	/* hp200 (68010) BSD binary */
#define	MID_HP300	300	/* hp300 (68020+68881) BSD binary */
#define	MID_HPUX	0x20C	/* hp200/300 HP-UX binary */
#define	MID_HPUX800     0x20B   /* hp800 HP-UX binary */

/*
 * a_flags
 */
#define EX_PIC		0x10	/* contains position independant code */
#define EX_DYNAMIC	0x20	/* contains run-time link-edit info */
#define EX_DPMASK	0x30	/* mask for the above */

```

## Code Walkthrough

```c
/*
 * execve() system call.
 */
int
execve(p, uap, retval)
	struct proc *p;
	register struct execve_args *uap;
	int *retval;
{
	struct nameidata nd, *ndp;
	int *stack_base;
	int error, len, i;
	struct image_params image_params, *imgp;
	struct vattr attr;

	imgp = &image_params;
	/*
	 * Initialize part of the common data
	 */
	imgp->proc = p;
	imgp->uap = uap;
	imgp->attr = &attr;
	imgp->image_header = NULL;
	imgp->argc = imgp->envc = 0;
	imgp->entry_addr = 0;
	imgp->vmspace_destroyed = 0;
	imgp->interpreted = 0;
	imgp->interpreter_name[0] = '\0';
	/*
	 * Allocate temporary demand zeroed space for argument and
	 *	environment strings
	 *//* ARG_MAX = 65536 */
	imgp->stringbase = (char *)kmem_alloc_wait(exec_map, ARG_MAX);
	if (imgp->stringbase == NULL) {
		error = ENOMEM;
		goto exec_fail;
	}
	imgp->stringp = imgp->stringbase;
	imgp->stringspace = ARG_MAX;
	/*
	 * Translate the file name. namei() returns a vnode pointer
	 *	in ni_vp amoung other things.
	 */
	ndp = &nd;
	NDINIT(ndp, LOOKUP, LOCKLEAF | FOLLOW | SAVENAME,
	    UIO_USERSPACE, uap->fname, p);

interpret:

	error = namei(ndp);
	if (error) {
		kmem_free_wakeup(exec_map, (vm_offset_t)imgp->stringbase, ARG_MAX);
		goto exec_fail;
	}
	imgp->vnodep = ndp->ni_vp;
	if (imgp->vnodep == NULL) {
		error = ENOEXEC;
		goto exec_fail_dealloc;
	}
	/*
	 * Check file permissions (also 'opens' file)
	 */
	error = exec_check_permissions(imgp);
	/*
	 * Lose the lock on the vnode. It's no longer needed, and must not
	 * exist for the pagefault paging to work below.
	 */
	VOP_UNLOCK(imgp->vnodep);

	if (error)
		goto exec_fail_dealloc;

	/*
	 * Map the image header (first page) of the file into
	 *	kernel address space
	 */
	error = vm_mmap(kernel_map,					/* map */
			(vm_offset_t *)&imgp->image_header, /* address */
			PAGE_SIZE,							/* size */
			VM_PROT_READ, 						/* protection */
			VM_PROT_READ, 						/* max protection */
			0,	 								/* flags */
			(caddr_t)imgp->vnodep,				/* vnode */
			0);									/* offset */
	if (error) {
		uprintf("mmap failed: %d\n",error);
		goto exec_fail_dealloc;
	}
	/*
	 * Loop through list of image activators, calling each one.
	 *	If there is no match, the activator returns -1. If there
	 *	is a match, but there was an error during the activation,
	 *	the error is returned. Otherwise 0 means success. If the
	 *	image is interpreted, loop back up and try activating
	 *	the interpreter.
	 *
	 *	execsw is a linker set where each item is a const struct execsw
	 */
	for (i = 0; execsw[i]; ++i) {
		if (execsw[i]->ex_imgact)
			error = (*execsw[i]->ex_imgact)(imgp);
		else
			continue;

		if (error == -1)
			continue;
		if (error)
			goto exec_fail_dealloc;

		/* Execve a shell script */
		if (imgp->interpreted) {
			/* free old vnode and name buffer */
			vrele(ndp->ni_vp);
			FREE(ndp->ni_cnd.cn_pnbuf, M_NAMEI);
			if (vm_map_remove(kernel_map, (vm_offset_t)imgp->image_header,
			    (vm_offset_t)imgp->image_header + PAGE_SIZE))
				panic("execve: header dealloc failed (1)");

			/* set new name to that of the interpreter */
			NDINIT(ndp, LOOKUP, LOCKLEAF | FOLLOW | SAVENAME,
			    UIO_SYSSPACE, imgp->interpreter_name, p);
			goto interpret;
		}
		break;
	}
	/* If we made it through all the activators and none matched, exit. */
	if (error == -1) {
		error = ENOEXEC;
		goto exec_fail_dealloc;
	}
	/*
	 * Copy out strings (args and env) and initialize stack base
	 */
	stack_base = exec_copyout_strings(imgp);
	p->p_vmspace->vm_minsaddr = (char *)stack_base;
	/*
	 * If custom stack fixup routine present for this process
	 * let it do the stack setup.
	 * Else stuff argument count as first item on stack
	 */
	if (p->p_sysent->sv_fixup)
		(*p->p_sysent->sv_fixup)(&stack_base, imgp);
	else
		suword(--stack_base, imgp->argc);

	/* close files on exec */
	fdcloseexec(p);

	/* reset caught signals */
	execsigs(p);

	/* name this process - nameiexec(p, ndp) */
	len = min(ndp->ni_cnd.cn_namelen,MAXCOMLEN);
	bcopy(ndp->ni_cnd.cn_nameptr, p->p_comm, len);
	p->p_comm[len] = 0;
	/*
	 * mark as executable, wakeup any process that was vforked and tell
	 * it that it now has it's own resources back
	 *//* P_PPWAIT := parent waiting for child to execve/exit */
	p->p_flag |= P_EXEC;
	if (p->p_pptr && (p->p_flag & P_PPWAIT)) {
		p->p_flag &= ~P_PPWAIT;
		wakeup((caddr_t)p->p_pptr);
	}
	/*
	 * Implement image setuid/setgid. Disallow if the process is
	 * being traced.
	 */
	if ((attr.va_mode & (VSUID | VSGID)) &&
	    (p->p_flag & P_TRACED) == 0) {
		/*
		 * Turn off syscall tracing for set-id programs, except for
		 * root.
		 *
		 * suser returns EPERM, or equiv 1, if ucred is not su's
		 */
		if (p->p_tracep && suser(p->p_ucred, &p->p_acflag)) {
			p->p_traceflag = 0;
			vrele(p->p_tracep);
			p->p_tracep = NULL;
		}
		/*
		 * Set the new credentials.
		 */
		p->p_ucred = crcopy(p->p_ucred);
		if (attr.va_mode & VSUID)
			p->p_ucred->cr_uid = attr.va_uid;
		if (attr.va_mode & VSGID)
			p->p_ucred->cr_groups[0] = attr.va_gid;
		p->p_flag |= P_SUGID;
	} else {
	        if (p->p_ucred->cr_uid == p->p_cred->p_ruid &&
		    p->p_ucred->cr_gid == p->p_cred->p_rgid)
			p->p_flag &= ~P_SUGID;
	}
	/*
	 * Implement correct POSIX saved-id behavior.
	 *
	 * In other words, save the actual uid of calling
	 * process.
	 */
	p->p_cred->p_svuid = p->p_ucred->cr_uid;
	p->p_cred->p_svgid = p->p_ucred->cr_gid;
	/*
	 * Store the vp for use in procfs
	 */
	if (p->p_textvp)		/* release old reference */
		vrele(p->p_textvp);
	VREF(ndp->ni_vp);
	p->p_textvp = ndp->ni_vp;
	/*
	 * If tracing the process, trap to debugger so breakpoints
	 * 	can be set before the program executes.
	 *//* P_TRACE := debugged proc being traced */
	if (p->p_flag & P_TRACED)
		psignal(p, SIGTRAP);

	/* clear "fork but no exec" flag, as we _are_ execing */
	p->p_acflag &= ~AFORK;

	/* Set entry address */
	setregs(p, imgp->entry_addr, (u_long)stack_base);

	/*
	 * free various allocated resources
	 */
	kmem_free_wakeup(exec_map, (vm_offset_t)imgp->stringbase, ARG_MAX);
	if (vm_map_remove(kernel_map, (vm_offset_t)imgp->image_header,
	    (vm_offset_t)imgp->image_header + PAGE_SIZE))
		panic("execve: header dealloc failed (2)");
	vrele(ndp->ni_vp);
	FREE(ndp->ni_cnd.cn_pnbuf, M_NAMEI);

	return (0);

exec_fail_dealloc:
	if (imgp->stringbase != NULL)
		kmem_free_wakeup(exec_map, (vm_offset_t)imgp->stringbase, ARG_MAX);
	if (imgp->image_header && imgp->image_header != (char *)-1)
		if (vm_map_remove(kernel_map, (vm_offset_t)imgp->image_header,
		    (vm_offset_t)imgp->image_header + PAGE_SIZE))
			panic("execve: header dealloc failed (3)");
	if (ndp->ni_vp) {
		vrele(ndp->ni_vp);
		FREE(ndp->ni_cnd.cn_pnbuf, M_NAMEI);
	}

exec_fail:
	if (imgp->vmspace_destroyed) {
		/* sorry, no more process anymore. exit gracefully */
		exit1(p, W_EXITCODE(0, SIGABRT));
		/* NOT REACHED */
		return(0);
	} else {
		return(error);
	}
}

int
exec_aout_imgact(iparams)
	struct image_params *iparams;
{
	struct exec *a_out = (struct exec *) iparams->image_header;
	struct vmspace *vmspace = iparams->proc->p_vmspace;
	unsigned long vmaddr, virtual_offset, file_offset;
	unsigned long bss_size;
	int error;

#ifdef COMPAT_LINUX
	/*
	 * Linux and *BSD binaries look very much alike,
	 * only the machine id is different:
	 * 0x64 for Linux, 0x86 for *BSD, 0x00 for BSDI.
	 */
	if (((a_out->a_magic >> 16) & 0xff) != 0x86 &&
	    ((a_out->a_magic >> 16) & 0xff) != 0)
                return -1;
#endif /* COMPAT_LINUX */
	/*
	 * Set file/virtual offset based on a.out variant.
	 *	We do two cases: host byte order and network byte order
	 *	(for NetBSD compatibility)
	 */
	switch ((int)(a_out->a_magic & 0xffff)) {
	case ZMAGIC:/* = 0430 = 118h */
		virtual_offset = 0;
		if (a_out->a_text) {
			file_offset = NBPG;
		} else {
			/* Bill's "screwball mode" */
			file_offset = 0;
		}
		break;
	case QMAGIC:/* = 0314 = CCh */
		virtual_offset = NBPG;
		file_offset = 0;
		break;
	default:
		/* NetBSD compatibility */
		switch ((int)(ntohl(a_out->a_magic) & 0xffff)) {
		case ZMAGIC:
		case QMAGIC:
			virtual_offset = NBPG;
			file_offset = 0;
			break;
		default:
			return (-1);
		}
	}
	bss_size = roundup(a_out->a_bss, NBPG);
	/*
	 * Check various fields in header for validity/bounds.
	 */
	if (/* entry point must lay with text region */
	    a_out->a_entry < virtual_offset ||
	    a_out->a_entry >= virtual_offset + a_out->a_text ||
	    /* text and data size must each be page rounded */
	    a_out->a_text % NBPG ||
	    a_out->a_data % NBPG)
		return (-1);

	/* text + data can't exceed file size */
	if (a_out->a_data + a_out->a_text > iparams->attr->va_size)
		return (EFAULT);

	/*
	 * text/data/bss must not exceed limits
	 */
	if (/* text can't exceed maximum text size */
	    a_out->a_text > MAXTSIZ ||
	    /* data + bss can't exceed maximum data size */
	    a_out->a_data + bss_size > MAXDSIZ ||
	    /* data + bss can't exceed rlimit */
	    a_out->a_data + bss_size >
		iparams->proc->p_rlimit[RLIMIT_DATA].rlim_cur)
			return (ENOMEM);

	/* copy in arguments and/or environment from old process */
	error = exec_extract_strings(iparams);
	if (error)
		return (error);
	/*
	 * Destroy old process VM and create a new one (with a new stack)
	 */
	exec_new_vmspace(iparams);
	/*
	 * Map text read/execute
	 */
	vmaddr = virtual_offset;
	error =
	    vm_mmap(&vmspace->vm_map,						/* map */
		&vmaddr,										/* address */
		a_out->a_text,									/* size */
		VM_PROT_READ | VM_PROT_EXECUTE,					/* protection */
		VM_PROT_READ | VM_PROT_EXECUTE | VM_PROT_WRITE,	/* max protection */
		MAP_PRIVATE | MAP_FIXED,						/* flags */
		(caddr_t)iparams->vnodep,						/* vnode */
		file_offset);									/* offset */
	if (error)
		return (error);
	/*
	 * Map data read/write (if text is 0, assume text is in data area
	 *	[Bill's screwball mode])
	 */
	vmaddr = virtual_offset + a_out->a_text;
	error =
	    vm_mmap(&vmspace->vm_map,
		&vmaddr,
		a_out->a_data,
		VM_PROT_READ | VM_PROT_WRITE | (a_out->a_text ? 0 : VM_PROT_EXECUTE),
		VM_PROT_ALL, MAP_PRIVATE | MAP_FIXED,
		(caddr_t) iparams->vnodep,
		file_offset + a_out->a_text);
	if (error)
		return (error);

	if (bss_size != 0) {
		/*
		 * Allocate demand-zeroed area for uninitialized data
		 * "bss" = 'block started by symbol' - named after the IBM 7090
		 *	instruction of the same name.
		 */
		vmaddr = virtual_offset + a_out->a_text + a_out->a_data;
		error = vm_map_find(&vmspace->vm_map, NULL, 0, &vmaddr, bss_size, FALSE);
		if (error)
			return (error);
	}

	/* Fill in process VM information */
	vmspace->vm_tsize = a_out->a_text >> PAGE_SHIFT;
	vmspace->vm_dsize = (a_out->a_data + bss_size) >> PAGE_SHIFT;
	vmspace->vm_taddr = (caddr_t) virtual_offset;
	vmspace->vm_daddr = (caddr_t) virtual_offset + a_out->a_text;

	/* Fill in image_params */
	iparams->interpreted = 0;
	iparams->entry_addr = a_out->a_entry;

	iparams->proc->p_sysent = &aout_sysvec;

	/* Indicate that this file should not be modified */
	iparams->vnodep->v_flag |= VTEXT;

	return (0);
}


```
