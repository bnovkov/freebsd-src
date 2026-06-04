#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/patch.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>

static int
patch_sysctl_hostname(SYSCTL_HANDLER_ARGS)
{
	char tmpname[MAXHOSTNAMELEN];
	int error, len;

	len = arg2;
	KASSERT(len <= sizeof(tmpname),
	    ("length %d too long for %s", len, __func__));

	strlcpy(tmpname, "PATCHED", len);

	error = sysctl_handle_string(oidp, tmpname, len, req);

	return (error);
}

static patch_func_t funcs[] = {
	{
		.old_sym = "sysctl_hostname",
		.new_addr = patch_sysctl_hostname,
	},
	{},
};

static patch_set_t patch = {
	.funcs = funcs,
};

static int
patch_handler(module_t mod, int cmd, void *arg)
{
	switch (cmd) {
	case MOD_LOAD:
		return patch_load_set(&patch);
	case MOD_UNLOAD:
		return patch_unload_set(&patch);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t mod_data = {
	"patch_example",
	patch_handler,
	0
};

DECLARE_MODULE(patch, mod_data, SI_SUB_KLD, SI_ORDER_ANY);
