/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dkuug.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * $FreeBSD$
 *
 * This module handles execution of a.out files which have been run through
 * "gzip".  This saves diskspace, but wastes cpu-cycles and VM.
 *
 * TODO:
 *	text-segments should be made R/O after being filled
 *	is the vm-stuff safe ?
 * 	should handle the entire header of gzip'ed stuff.
 *	inflate isn't quite reentrant yet...
 *	error-handling is a mess...
 *	so is the rest...
 *	tidy up unnecesary includes
 */

#include <sys/param.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/imgact_aout.h>
#include <sys/kernel.h>
#include <sys/mman.h>
#include <sys/resourcevar.h>
#include <sys/sysent.h>
#include <sys/systm.h>
#include <sys/inflate.h>

#include <vm/vm.h>
#include <vm/vm_kern.h>

struct imgact_gzip {
	struct image_params *ip;
	struct exec     a_out;
	int             error;
	int             where;
	u_char         *inbuf;
	u_long          offset;
	u_long          output;
	u_long          len;
	int             idx;
	u_long          virtual_offset, file_offset, file_end, bss_size;
};

static int NextByte __P((void *vp));
static int do_aout_hdr __P((struct imgact_gzip *));
static int Flush __P((void *vp, u_char *, u_long siz));

int
exec_gzip_imgact(iparams)
	struct image_params *iparams;
{
	int             error, error2 = 0;
	u_char         *p = (u_char *) iparams->image_header;
	struct imgact_gzip igz;
	struct inflate  infl;

	/* If these four are not OK, it isn't a gzip file */
	if (p[0] != 0x1f)
		return -1;	/* 0    Simply magic	 */
	if (p[1] != 0x8b)
		return -1;	/* 1    Simply magic	 */
	if (p[2] != 0x08)
		return -1;	/* 2    Compression method	 */
	if (p[9] != 0x03)
		return -1;	/* 9    OS compressed on	 */

	/*
	 * If this one contains anything but a comment or a filename marker,
	 * we don't want to chew on it
	 */
	if (p[3] & ~(0x18))
		return ENOEXEC;	/* 3    Flags		 */

	/* These are of no use to us */
	/* 4-7  Timestamp		 */
	/* 8    Extra flags		 */

	bzero(&igz, sizeof igz);
	bzero(&infl, sizeof infl);
	infl.gz_private = (void *) &igz;
	infl.gz_input = NextByte;
	infl.gz_output = Flush;

	igz.ip = iparams;
	igz.idx = 10;

	if (p[3] & 0x08) {	/* skip a filename */
		while (p[igz.idx++])
			if (igz.idx >= PAGE_SIZE)
				return ENOEXEC;
	}
	if (p[3] & 0x10) {	/* skip a comment */
		while (p[igz.idx++])
			if (igz.idx >= PAGE_SIZE)
				return ENOEXEC;
	}
	igz.len = igz.ip->attr->va_size;

	error = inflate(&infl);

	if (igz.inbuf) {
		error2 =
			vm_map_remove(kernel_map, (vm_offset_t) igz.inbuf,
			    (vm_offset_t) igz.inbuf + PAGE_SIZE);
	}
	if (igz.error || error || error2) {
		printf("Output=%lu ", igz.output);
		printf("Inflate_error=%d igz.error=%d error2=%d where=%d\n",
		       error, igz.error, error2, igz.where);
	}
	if (igz.error)
		return igz.error;
	if (error)
		return ENOEXEC;
	if (error2)
		return error2;
	return 0;
}

static int
do_aout_hdr(struct imgact_gzip * gz)
{
	int             error;
	struct vmspace *vmspace = gz->ip->proc->p_vmspace;
	u_long          vmaddr;

	/*
	 * Set file/virtual offset based on a.out variant. We do two cases:
	 * host byte order and network byte order (for NetBSD compatibility)
	 */
	switch ((int) (gz->a_out.a_magic & 0xffff)) {
	case ZMAGIC:
		gz->virtual_offset = 0;
		if (gz->a_out.a_text) {
			gz->file_offset = NBPG;
		} else {
			/* Bill's "screwball mode" */
			gz->file_offset = 0;
		}
		break;
	case QMAGIC:
		gz->virtual_offset = NBPG;
		gz->file_offset = 0;
		break;
	default:
		/* NetBSD compatibility */
		switch ((int) (ntohl(gz->a_out.a_magic) & 0xffff)) {
		case ZMAGIC:
		case QMAGIC:
			gz->virtual_offset = NBPG;
			gz->file_offset = 0;
			break;
		default:
			gz->where = __LINE__;
			return (-1);
		}
	}

	gz->bss_size = roundup(gz->a_out.a_bss, NBPG);

	/*
	 * Check various fields in header for validity/bounds.
	 */
	if (			/* entry point must lay with text region */
	    gz->a_out.a_entry < gz->virtual_offset ||
	    gz->a_out.a_entry >= gz->virtual_offset + gz->a_out.a_text ||

	/* text and data size must each be page rounded */
	    gz->a_out.a_text % NBPG ||
	    gz->a_out.a_data % NBPG) {
		gz->where = __LINE__;
		return (-1);
	}
	/*
	 * text/data/bss must not exceed limits
	 */
	if (			/* text can't exceed maximum text size */
	    gz->a_out.a_text > MAXTSIZ ||

	/* data + bss can't exceed maximum data size */
	    gz->a_out.a_data + gz->bss_size > MAXDSIZ ||

	/* data + bss can't exceed rlimit */
	    gz->a_out.a_data + gz->bss_size >
	    gz->ip->proc->p_rlimit[RLIMIT_DATA].rlim_cur) {
		gz->where = __LINE__;
		return (ENOMEM);
	}
	/* Find out how far we should go */
	gz->file_end = gz->file_offset + gz->a_out.a_text + gz->a_out.a_data;

	/* copy in arguments and/or environment from old process */
	error = exec_extract_strings(gz->ip);
	if (error) {
		gz->where = __LINE__;
		return (error);
	}
	/*
	 * Destroy old process VM and create a new one (with a new stack)
	 */
	exec_new_vmspace(gz->ip);

	vmaddr = gz->virtual_offset;

	error = vm_mmap(&vmspace->vm_map,	/* map */
			&vmaddr,/* address */
			gz->a_out.a_text,	/* size */
			VM_PROT_READ | VM_PROT_EXECUTE | VM_PROT_WRITE,	/* protection */
			VM_PROT_READ | VM_PROT_EXECUTE | VM_PROT_WRITE,
			MAP_ANON | MAP_FIXED,	/* flags */
			0,	/* vnode */
			0);	/* offset */

	if (error) {
		gz->where = __LINE__;
		return (error);
	}
	vmaddr = gz->virtual_offset + gz->a_out.a_text;

	/*
	 * Map data read/write (if text is 0, assume text is in data area
	 * [Bill's screwball mode])
	 */

	error = vm_mmap(&vmspace->vm_map,
			&vmaddr,
			gz->a_out.a_data,
			VM_PROT_READ | VM_PROT_WRITE | (gz->a_out.a_text ? 0 : VM_PROT_EXECUTE),
			VM_PROT_ALL, MAP_ANON | MAP_FIXED,
			0,
			0);

	if (error) {
		gz->where = __LINE__;
		return (error);
	}
	if (gz->bss_size != 0) {
		/*
		 * Allocate demand-zeroed area for uninitialized data "bss" = 'block
		 * started by symbol' - named after the IBM 7090 instruction of the
		 * same name.
		 */
		vmaddr = gz->virtual_offset + gz->a_out.a_text + gz->a_out.a_data;
		error = vm_map_find(&vmspace->vm_map, NULL, 0, &vmaddr, gz->bss_size, FALSE);
		if (error) {
			gz->where = __LINE__;
			return (error);
		}
	}
	/* Fill in process VM information */
	vmspace->vm_tsize = gz->a_out.a_text >> PAGE_SHIFT;
	vmspace->vm_dsize = (gz->a_out.a_data + gz->bss_size) >> PAGE_SHIFT;
	vmspace->vm_taddr = (caddr_t) gz->virtual_offset;
	vmspace->vm_daddr = (caddr_t) gz->virtual_offset + gz->a_out.a_text;

	/* Fill in image_params */
	gz->ip->interpreted = 0;
	gz->ip->entry_addr = gz->a_out.a_entry;

	gz->ip->proc->p_sysent = &aout_sysvec;

	return 0;
}

static int
NextByte(void *vp)
{
	int             error;
	struct imgact_gzip *igz = (struct imgact_gzip *) vp;

	if (igz->idx >= igz->len) {
		igz->where = __LINE__;
		return GZ_EOF;
	}
	if (igz->inbuf && igz->idx < (igz->offset + PAGE_SIZE)) {
		return igz->inbuf[(igz->idx++) - igz->offset];
	}
	if (igz->inbuf) {
		error = vm_map_remove(kernel_map, (vm_offset_t) igz->inbuf,
			    (vm_offset_t) igz->inbuf + PAGE_SIZE);
		if (error) {
			igz->where = __LINE__;
			igz->error = error;
			return GZ_EOF;
		}
	}
	igz->offset = igz->idx & ~PAGE_MASK;

	error = vm_mmap(kernel_map,	/* map */
			(vm_offset_t *) & igz->inbuf,	/* address */
			PAGE_SIZE,	/* size */
			VM_PROT_READ,	/* protection */
			VM_PROT_READ,	/* max protection */
			0,	/* flags */
			(caddr_t) igz->ip->vnodep,	/* vnode */
			igz->offset);	/* offset */
	if (error) {
		igz->where = __LINE__;
		igz->error = error;
		return GZ_EOF;
	}
	return igz->inbuf[(igz->idx++) - igz->offset];
}

static int
Flush(void *vp, u_char * ptr, u_long siz)
{
	struct imgact_gzip *gz = (struct imgact_gzip *) vp;
	u_char         *p = ptr, *q;
	int             i;

	/* First, find a a.out-header */
	if (gz->output < sizeof gz->a_out) {
		q = (u_char *) & gz->a_out;
		i = min(siz, sizeof gz->a_out - gz->output);
		bcopy(p, q + gz->output, i);
		gz->output += i;
		p += i;
		siz -= i;
		if (gz->output == sizeof gz->a_out) {
			i = do_aout_hdr(gz);
			if (i == -1) {
				if (!gz->where)
					gz->where = __LINE__;
				gz->error = ENOEXEC;
				return ENOEXEC;
			} else if (i) {
				gz->where = __LINE__;
				gz->error = i;
				return ENOEXEC;
			}
			if (gz->file_offset < sizeof gz->a_out) {
				q = (u_char *) gz->virtual_offset + gz->output - gz->file_offset;
				bcopy(&gz->a_out, q, sizeof gz->a_out - gz->file_offset);
			}
		}
	}
	/* Skip over zero-padded first PAGE if needed */
	if (gz->output < gz->file_offset && (gz->output + siz) > gz->file_offset) {
		i = min(siz, gz->file_offset - gz->output);
		gz->output += i;
		p += i;
		siz -= i;
	}
	if (gz->output >= gz->file_offset && gz->output < gz->file_end) {
		i = min(siz, gz->file_end - gz->output);
		q = (u_char *) gz->virtual_offset + gz->output - gz->file_offset;
		bcopy(p, q, i);
		gz->output += i;
		p += i;
		siz -= i;
	}
	gz->output += siz;
	return 0;
}


/*
 * Tell kern_execve.c about it, with a little help from the linker.
 * Since `const' objects end up in the text segment, TEXT_SET is the
 * correct directive to use.
 */

static const struct execsw gzip_execsw = {exec_gzip_imgact, "gzip"};
TEXT_SET(execsw_set, gzip_execsw);
