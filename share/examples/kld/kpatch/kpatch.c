#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>

// TODO: How to cleanly include the header from tools?
#include "../../../../tools/tools/buildpatch/buildpatch.h"

#define HELPER(str) \
	do { \
		char tmpname[MAXHOSTNAMELEN]; \
		int error, len; \
		len = arg2; \
		KASSERT(len <= sizeof(tmpname), \
		    ("length %d too long for %s", len, __func__)); \
		strlcpy(tmpname, str, len); \
		error = sysctl_handle_string(oidp, tmpname, len, req); \
		return (error); \
	} while (0)

static int
patch_sysctl_hostname1(SYSCTL_HANDLER_ARGS)
{
	HELPER("PATCHED");
}
PATCH_FUNC(test1, patch_sysctl_hostname1,
	   "sysctl_hostname", "kernel", "kern_mib.c");

static int
patch_sysctl_hostname2(SYSCTL_HANDLER_ARGS)
{
	HELPER("HELLO");
}
PATCH_FUNC(test2, patch_sysctl_hostname2,
	   "sysctl_hostname", "kernel", "kern_mib.c");

static void
patch_test3(void)
{
	panic("Not supposed to work\n");
}
PATCH_FUNC(test3, patch_test3,
	   "sys___sysctl", "kernel", "kern_sysctl.c");

PATCH_DECLARE(test1, 0);
PATCH_DECLARE(test2, 0);
PATCH_DECLARE(test3, 0);
