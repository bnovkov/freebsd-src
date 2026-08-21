#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>

#include <buildpatch.h>

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

static int
pre_patch1(void)
{
	printf("Patching test1 (pre)\n");
	return (0);
}

static void
post_patch1(int x)
{
	printf("Patching test1 (post) -> %d\n", x);
}

PATCH_DECLARE_FULL(test1, 0,
		pre_patch1, post_patch1,
		pre_patch1, post_patch1);

PATCH_DECLARE(test2, 0);
PATCH_DECLARE(test3, 0);

/*
 * Example to see if custom relocs work
 */
extern void vga_suspend(void *);
PATCH_RELOC(vga_suspend, "vga_suspend", "kernel", "vga_isa.c");

extern int loadcnt;
PATCH_RELOC(loadcnt, "loadcnt", "kernel", "kern_linker.c");

extern void linker_init(void *arg);
PATCH_RELOC(linker_init, "linker_init", "kernel", "kern_linker.c");

void *rel = vga_suspend;

static void
kpatch_sysinit(void *dummy __unused)
{
	printf("vga_suspend was relocated to %p\n", rel);
	printf("loadcnt was relocated to %p\n", &loadcnt);
	printf("linker_init was relocated to %p\n", linker_init);
}

SYSINIT(kpatch_mod, SI_SUB_KLD, SI_ORDER_ANY, kpatch_sysinit, NULL);
