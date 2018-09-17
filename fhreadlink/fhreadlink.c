/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2018 Gandi SAS
 * Copyright (c) 1999 Assar Westerlund
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
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

struct fhreadlink_args {
	fhandle_t	*fhp;
	char		*buf;
	size_t		bufsize;
};

int sys_fhreadlink(struct thread *td, void *params);

/*
 * The function for implementing the syscall.
 */
int sys_fhreadlink(struct thread *td, void *params)
{
	struct fhreadlink_args *uap;
	fhandle_t fh;
	struct mount *mp;
	struct vnode *vp;
	struct uio auio;
	struct iovec aiov;
	int error;

	uap = (struct fhreadlink_args*)params;

	error = priv_check(td, PRIV_VFS_GETFH);
	if (error != 0)
		return (error);

	if (uap->bufsize > IOSIZE_MAX)
		return (EINVAL);

	error = copyin(uap->fhp, &fh, sizeof(fh));
	if (error != 0)
		return (error);

	if ((mp = vfs_busyfs(&fh.fh_fsid)) == NULL)
		return (ESTALE);

	error = VFS_FHTOVP(mp, &fh.fh_fid, LK_EXCLUSIVE, &vp);
        vfs_unbusy(mp);
        if (error != 0)
                return (error);

	/* code taken from kern_readlinkat */
#ifdef VV_READLINK
	if (vp->v_type != VLNK && (vp->v_vflag & VV_READLINK) == 0)
#else
	if (vp->v_type != VLNK)
#endif
		error = EINVAL;
	else {
		aiov.iov_base = uap->buf;
		aiov.iov_len = uap->bufsize;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = 0;
		auio.uio_rw = UIO_READ;
		auio.uio_segflg = UIO_USERSPACE;
		auio.uio_td = td;
		auio.uio_resid = uap->bufsize;
		error = VOP_READLINK(vp, &auio, td->td_ucred);
		td->td_retval[0] = uap->bufsize - auio.uio_resid;
        }
	vput(vp);
	return (error);
}

/*
 * The `sysent' for the new syscall
 */
static struct sysent fhreadlink_sysent = {
	3,			/* sy_narg */
	sys_fhreadlink		/* sy_call */
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
		printf("fhreadlink syscall loaded at %d\n", offset);
		break;
	case MOD_UNLOAD :
		printf("fhreadlink syscall unloaded from %d\n", offset);
		break;
	default :
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

SYSCALL_MODULE(fhreadlink, &offset, &fhreadlink_sysent, load, NULL);
