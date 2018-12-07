/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2018 Gandi SAS
 * Copyright (c) 1999 Assar Westerlund
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
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

struct getfhat_args {
	int		fd;
	char		*path;
	fhandle_t	*fhp;
	int		flag;
};

int sys_getfhat(struct thread *td, void *params);

/*
 * The function for implementing the syscall.
 */
int sys_getfhat(struct thread *td, void *params)
{
	struct getfhat_args *uap;
	struct nameidata nd;
	fhandle_t fh;
	struct vnode *vp;
	cap_rights_t rights;
	int error;

	uap = (struct getfhat_args*)params;

	error = priv_check(td, PRIV_VFS_GETFH);
	if (error != 0)
		return (error);

	NDINIT_AT(&nd, LOOKUP, (uap->flag & AT_SYMLINK_NOFOLLOW ? NOFOLLOW : FOLLOW) | LOCKLEAF | AUDITVNODE1,
		UIO_USERSPACE, uap->path ? uap->path : ".", uap->fd, td);

	error = namei(&nd);
	if (error != 0)
		return (error);
	NDFREE(&nd, NDF_ONLY_PNBUF);
	vp = nd.ni_vp;

        bzero(&fh, sizeof(fh));
        fh.fh_fsid = vp->v_mount->mnt_stat.f_fsid;
        error = VOP_VPTOFH(vp, &fh.fh_fid);
        vput(vp);
        if (error == 0)
		error = copyout(&fh, uap->fhp, sizeof (fh));
	return (error);
}

/*
 * The `sysent' for the new syscall
 */
static struct sysent getfhat_sysent = {
	4,			/* sy_narg */
	sys_getfhat		/* sy_call */
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
		printf("getfhat syscall loaded at %d\n", offset);
		break;
	case MOD_UNLOAD :
		printf("getfhat syscall unloaded from %d\n", offset);
		break;
	default :
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

SYSCALL_MODULE(getfhat, &offset, &getfhat_sysent, load, NULL);
