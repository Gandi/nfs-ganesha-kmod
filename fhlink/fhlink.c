/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2018 Gandi SAS
 * Copyright (c) 1999 Assar Westerlund
 * Copyright (c) 1989, 1993
 *      The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
#include <sys/namei.h>
#include <sys/mount.h>
#include <sys/priv.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/capsicum.h>
#include <sys/buf.h>

struct fhlink_args {
	fhandle_t	*fhp;
	int		tofd;
	const char	*to;
};

int sys_fhlink(struct thread *td, void *params);

extern int hardlink_check_uid;
extern int hardlink_check_gid;

static int
can_hardlink(struct vnode *vp, struct ucred *cred)
{
	struct vattr va;
	int error;

	if (!hardlink_check_uid && !hardlink_check_gid)
		return (0);

	error = VOP_GETATTR(vp, &va, cred);
	if (error != 0)
		return (error);

	if (hardlink_check_uid && cred->cr_uid != va.va_uid) {
		error = priv_check_cred(cred, PRIV_VFS_LINK, 0);
		if (error != 0)
			return (error);
	}

	if (hardlink_check_gid && !groupmember(va.va_gid, cred)) {
		error = priv_check_cred(cred, PRIV_VFS_LINK, 0);
		if (error != 0)
			return (error);
	}

	return (0);
}

/*
 * The function for implementing the syscall.
 */
int sys_fhlink(struct thread *td, void *params)
{
	struct fhlink_args *uap;
	fhandle_t fh;
	struct mount *mp;
	struct vnode *vp;
	struct nameidata nd;
	cap_rights_t rights;
	int error;

	uap = (struct fhlink_args*)params;

	error = priv_check(td, PRIV_VFS_GETFH);
	if (error != 0)
		return (error);

	error = copyin(uap->fhp, &fh, sizeof(fh));
	if (error != 0)
		return (error);

again:
	bwillwrite();
	if ((mp = vfs_busyfs(&fh.fh_fsid)) == NULL)
		return (ESTALE);

	error = VFS_FHTOVP(mp, &fh.fh_fid, LK_EXCLUSIVE, &vp);
        vfs_unbusy(mp);
        if (error != 0)
                return (error);

	/* code taken from kern_linkat */
	if (vp->v_type == VDIR) {
		vput(vp);
		return (EPERM);		/* POSIX */
	}

	NDINIT_ATRIGHTS(&nd, CREATE,
	    LOCKPARENT | SAVENAME | AUDITVNODE2 | NOCACHE, UIO_USERSPACE, uap->to, uap->tofd,
	    cap_rights_init(&rights, CAP_LINKAT_TARGET), td);
	if ((error = namei(&nd)) == 0) {
		if (nd.ni_vp != NULL) {
			NDFREE(&nd, NDF_ONLY_PNBUF);
			if (nd.ni_dvp == nd.ni_vp)
				vrele(nd.ni_dvp);
			else
				vput(nd.ni_dvp);
			vrele(nd.ni_vp);
			vput(vp);
			return (EEXIST);
		} else if (nd.ni_dvp->v_mount != vp->v_mount) {
			/*
			 * Cross-device link.  No need to recheck
			 * vp->v_type, since it cannot change, except
			 * to VBAD.
			 */
			NDFREE(&nd, NDF_ONLY_PNBUF);
			vput(nd.ni_dvp);
			vput(vp);
			return (EXDEV);
		} else {
			/*
			 * if we got there, vp should be locked thanks to VFS_FHTOVP 
			 * if ((error = vn_lock(vp, LK_EXCLUSIVE)) == 0) {
			 */
			error = can_hardlink(vp, td->td_ucred);
#ifdef MAC
			if (error == 0)
				error = mac_vnode_check_link(td->td_ucred,
				    nd.ni_dvp, vp, &nd.ni_cnd);
#endif
			if (error != 0) {
				vput(vp);
				vput(nd.ni_dvp);
				NDFREE(&nd, NDF_ONLY_PNBUF);
				return (error);
			}
			error = vn_start_write(vp, &mp, V_NOWAIT);
			if (error != 0) {
				vput(vp);
				vput(nd.ni_dvp);
				NDFREE(&nd, NDF_ONLY_PNBUF);
				error = vn_start_write(NULL, &mp,
				    V_XSLEEP | PCATCH);
				if (error != 0)
					return (error);
				goto again;
			}
			error = VOP_LINK(nd.ni_dvp, vp, &nd.ni_cnd);
			vput(nd.ni_dvp);
			vn_finished_write(mp);
			NDFREE(&nd, NDF_ONLY_PNBUF);
		}
	}
	vput(vp);
	return (error);
}

/*
 * The `sysent' for the new syscall
 */
static struct sysent fhlink_sysent = {
	3,			/* sy_narg */
	sys_fhlink		/* sy_call */
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
		printf("fhlink syscall loaded at %d\n", offset);
		break;
	case MOD_UNLOAD :
		printf("fhlink syscall unloaded from %d\n", offset);
		break;
	default :
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

SYSCALL_MODULE(fhlink, &offset, &fhlink_sysent, load, NULL);
