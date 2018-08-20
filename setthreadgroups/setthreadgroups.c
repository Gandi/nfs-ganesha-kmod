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
#include <sys/lock.h>

#include <security/audit/audit.h>

struct setthreadgroups_args {
	u_int	gidsetsize;
	gid_t	*gidset;
};

int sys_setthreadgroups(struct thread *td, void *params);

static void
crsetgroups_locked(struct ucred *cr, int ngrp, gid_t *groups)
{
	int i;
	int j;
	gid_t g;
	
	KASSERT(cr->cr_agroups >= ngrp, ("cr_ngroups is too small"));

	bcopy(groups, cr->cr_groups, ngrp * sizeof(gid_t));
	cr->cr_ngroups = ngrp;

	/*
	 * Sort all groups except cr_groups[0] to allow groupmember to
	 * perform a binary search.
	 *
	 * XXX: If large numbers of groups become common this should
	 * be replaced with shell sort like linux uses or possibly
	 * heap sort.
	 */
	for (i = 2; i < ngrp; i++) {
		g = cr->cr_groups[i];
		for (j = i-1; j >= 1 && g < cr->cr_groups[j]; j--)
			cr->cr_groups[j + 1] = cr->cr_groups[j];
		cr->cr_groups[j + 1] = g;
	}
}

static int
kern_setthreadgroups(struct thread *td, u_int ngrp, gid_t *groups)
{
	struct ucred *newcred, *oldcred;
	int error;

	MPASS(ngrp <= ngroups_max + 1);
	AUDIT_ARG_GROUPSET(groups, ngrp);
	newcred = crget();
	crextend(newcred, ngrp);

	oldcred = td->td_ucred;
	crcopy(newcred, oldcred);

#ifdef MAC
	error = mac_cred_check_setgroups(oldcred, ngrp, groups);
	if (error)
		goto fail;
#endif

	error = priv_check_cred(oldcred, PRIV_CRED_SETGROUPS, 0);
	if (error)
		goto fail;

	if (ngrp == 0) {
		/*
		 * setgroups(0, NULL) is a legitimate way of clearing the
		 * groups vector on non-BSD systems (which generally do not
		 * have the egid in the groups[0]).  We risk security holes
		 * when running non-BSD software if we do not do the same.
		 */
		newcred->cr_ngroups = 1;
	} else {
		crsetgroups_locked(newcred, ngrp, groups);
	}
	td->td_ucred = newcred;
	crfree(oldcred);
	return (0);

fail:
	crfree(newcred);
	return (error);
}

/*
 * The function for implementing the syscall.
 */
int sys_setthreadgroups(struct thread *td, void *params)
{
	struct setthreadgroups_args *uap;
	gid_t smallgroups[XU_NGROUPS];
	gid_t *groups;
	u_int gidsetsize;
	int error;

	uap = (struct setthreadgroups_args*)params;

	gidsetsize = uap->gidsetsize;
	if (gidsetsize > ngroups_max + 1)
		return (EINVAL);

	if (gidsetsize > XU_NGROUPS)
		groups = malloc(gidsetsize * sizeof(gid_t), M_TEMP, M_WAITOK);
	else
		groups = smallgroups;

	error = copyin(uap->gidset, groups, gidsetsize * sizeof(gid_t));
	if (error == 0)
		error = kern_setthreadgroups(td, gidsetsize, groups);

	if (gidsetsize > XU_NGROUPS)
		free(groups, M_TEMP);
	return (error);

}

/*
 * The `sysent' for the new syscall
 */
static struct sysent setthreadgroups_sysent = {
	2,			/* sy_narg */
	sys_setthreadgroups		/* sy_call */
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
		printf("setthreadgroups syscall loaded at %d\n", offset);
		break;
	case MOD_UNLOAD :
		printf("setthreadgroups syscall unloaded from %d\n", offset);
		break;
	default :
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

SYSCALL_MODULE(setthreadgroups, &offset, &setthreadgroups_sysent, load, NULL);
