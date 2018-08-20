/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2018 Gandi SAS
 * Copyright (c) 1999 Assar Westerlund
 * Copyright (c) 1982, 1986, 1989, 1990, 1991, 1993
 *	The Regents of the University of California.
 * (c) UNIX System Laboratories, Inc.
 * Copyright (c) 2000-2001 Robert N. M. Watson.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
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
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/priv.h>
#include <sys/resourcevar.h>

#include <security/audit/audit.h>

struct setthreadgid_args {
	gid_t	gid;
};

int sys_setthreadgid(struct thread *td, void *params);

/*
 * The function for implementing the syscall.
 */
int sys_setthreadgid(struct thread *td, void *params)
{
	struct setthreadgid_args *uap;
	struct ucred *newcred, *oldcred;
	gid_t egid;
	int error;

	uap = (struct setthreadgid_args*)params;
	egid = uap->gid;

	/* code taken from setegid */

	AUDIT_ARG_EGID(egid);
	newcred = crget();

	oldcred = td->td_ucred;
	crcopy(newcred, oldcred);

#ifdef MAC
	error = mac_cred_check_setegid(oldcred, egid);
	if (error)
		goto fail;
#endif

	if (egid != oldcred->cr_rgid &&		/* allow setegid(getgid()) */
	    egid != oldcred->cr_svgid &&	/* allow setegid(saved gid) */
	    (error = priv_check_cred(oldcred, PRIV_CRED_SETEGID, 0)) != 0)
		goto fail;

	/*
	 * Everything's okay, do it.
	 */
	if (oldcred->cr_groups[0] != egid) {
		change_egid(newcred, egid);
	}
	td->td_ucred = newcred;
	crfree(oldcred);
	return (0);

fail:
	crfree(newcred);
	return (error);
}

/*
 * The `sysent' for the new syscall
 */
static struct sysent setthreadgid_sysent = {
	1,			/* sy_narg */
	sys_setthreadgid		/* sy_call */
};

/*
 * The offset in sysent where the syscall is allocated.
 */
static int offset = NO_SYSCALL;

/*
 * The function called at load/unload.
 */
static int
load(struct module *module, int cmd, void *arg)
{
	int error = 0;

	switch (cmd) {
	case MOD_LOAD :
		printf("setthreadgid syscall loaded at %d\n", offset);
		break;
	case MOD_UNLOAD :
		printf("setthreadgid syscall unloaded from %d\n", offset);
		break;
	default :
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

SYSCALL_MODULE(setthreadgid, &offset, &setthreadgid_sysent, load, NULL);
