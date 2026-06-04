#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/cdefs.h>
#include <sys/kernel.h>
#include <sys/patch.h>

static TAILQ_HEAD(, patch_set) patch_list = TAILQ_HEAD_INITIALIZER(patch_list);

int
patch_excluded(const char *name)
{
	if (strncmp(name, "patch_", 6) == 0)
		return (1);

	if (strncmp(name, "db_", 3) == 0 ||
	    strncmp(name, "kdb_", 4) == 0)
		return (1);

	if (strcmp(name, "owner_mtx") == 0 ||
	    strcmp(name, "owner_rm") == 0 ||
	    strcmp(name, "owner_rw") == 0 ||
	    strcmp(name, "owner_sx") == 0)
		return (1);

	if (strncmp(name, "__msan", 6) == 0 ||
	    strncmp(name, "kmsan_", 6) == 0)
		return (1);

	if (strcmp(name, "unwind_frame") == 0)
		return (1);

	return (0);
}

int patch_load_set(patch_set_t *patch)
{
	return (-1);
}

int patch_unload_set(patch_set_t *patch)
{
	return (-1);
}

static void
patch_init(void *dummy __unused)
{
	printf("patch: initialized subsystem\n");
}

SYSINIT(patch, SI_SUB_KLD, SI_ORDER_ANY, patch_init,
    NULL);
