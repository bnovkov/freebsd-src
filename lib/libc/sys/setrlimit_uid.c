/*
 * Copyright (c) Bojan Novković <bnovkov@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "namespace.h"
#define _WANT_P_OSREL
#include <sys/param.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "libc_private.h"

#pragma weak setrlimit_uid
int setrlimit_uid(u_int which, struct rlimit *rlp, uid_t uid)
{
	if (__getosreldate() >= P_OSREL_SETRLIMIT_UID)
		return (INTERPOS_SYS(setrlimit_uid, which, rlp, uid));
	return (__sys_setrlimit(which, rlp));
}
