/*
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)profile.h	8.1 (Berkeley) 6/11/93
 * $FreeBSD$
 */

#ifndef _I386_MACHINE_PROFILE_H_
#define _I386_MACHINE_PROFILE_H_

#define	_MCOUNT_DECL static inline void _mcount

#define	MCOUNT \
extern void mcount() asm("mcount"); void mcount() { \
	int selfpc, frompcindex; \
	/* \
	 * find the return address for mcount, \
	 * and the return address for mcount's caller. \
	 * \
	 * selfpc = pc pushed by mcount call \
	 */ \
	asm("movl 4(%%ebp),%0" : "=r" (selfpc)); \
	/* \
	 * frompcindex = pc pushed by jsr into self. \
	 * In GCC the caller's stack frame has already been built so we \
	 * have to chase a6 to find caller's raddr. \
	 */ \
	asm("movl (%%ebp),%0" : "=r" (frompcindex)); \
	frompcindex = ((int *)frompcindex)[1]; \
	_mcount(frompcindex, selfpc); \
}

#define MCOUNT_ENTER    save_eflags = read_eflags(); disable_intr()
#define MCOUNT_EXIT     write_eflags(save_eflags)

#endif
