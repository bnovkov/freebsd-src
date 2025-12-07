/*
 * Copyright (c) 2019 John Baldwin <jhb@FreeBSD.org>
 * Copyright (c) 2025 Bojan Novković <bnovkov@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/nv_namespace.h>

#include <errno.h>
#include <malloc.h>
#include <string.h>

#include "bhyve/config.h"
#include "bhyve/net_backends.h"
#include "bhyve/pci.h"
#include "internal.h"

struct devinfo {
	const char *name;
	int (*init_fds)(nvlist_t *);
	bool (*validate_hotplug_request)(nvlist_t *);
	int (*legacy_config)(nvlist_t *, const char *);
};
SET_DECLARE(pci_devinfo, struct devinfo);

static struct devinfo *
find_devinfo(const char *device)
{
	struct devinfo **di;

	SET_FOREACH(di, pci_devinfo) {
		if (strncmp(device, (*di)->name, strlen(device)) == 0) {
			return (*di);
		}
	}

	return (NULL);
}

bool
pci_validate_hotplug_request(nvlist_t *nvl, const char *device)
{
	struct devinfo *di;

	if (device == NULL)
		return (false);
	if (!nvlist_exists_bool(nvl, "ipc")) {
		nvlist_add_string(nvl, "error", "not a hotplug request");
		return (false);
	}

	di = find_devinfo(device);
	if (di == NULL || di->validate_hotplug_request == NULL)
		return (true);

	return (di->validate_hotplug_request(nvl));
}

int
pci_init_fds(nvlist_t *nvl, const char *device)
{
	struct devinfo *di;

	if (device == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (nvlist_exists_bool(nvl, "ipc")) {
		/*
		 * We're dealing with a hotplug request, all
		 * descriptors should've been setup by now.
		 */
		return (0);
	}
	di = find_devinfo(device);
	if (di == NULL || di->init_fds == NULL)
		return (0);

	return (di->init_fds(nvl));
}

int
pci_parse_config(nvlist_t *nvl, const char *device, const char *config)
{
	struct devinfo *di;

	if (device == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (nvlist_exists_bool(nvl, "ipc") || config == NULL)
		return (0);
	di = find_devinfo(device);
	if (di == NULL || di->legacy_config == NULL)
		return (0);

	return (di->legacy_config(nvl, config));
}

/*
 * Helper function to parse a list of comma-separated options where
 * each option is formatted as "name[=value]".  If no value is
 * provided, the option is treated as a boolean and is given a value
 * of true.
 */
int
pci_parse_legacy_config(nvlist_t *nvl, const char *opt)
{
	char *config, *name, *tofree, *value;

	if (opt == NULL)
		return (0);

	config = tofree = strdup(opt);
	while ((name = strsep(&config, ",")) != NULL) {
		value = strchr(name, '=');
		if (value != NULL) {
			*value = '\0';
			value++;
			set_config_value_node(nvl, name, value);
		} else
			set_config_bool_node(nvl, name, true);
	}
	free(tofree);
	return (0);
}

/*
 * Per-device file initialization routines.
 */
static struct devinfo e1000_info = {
	.name = "e1000",
	.init_fds = netbe_init_fds,
	.legacy_config = netbe_legacy_config,
	.validate_hotplug_request = netbe_validate_hotplug_request
};

static struct devinfo virtio_net_info = {
	.name = "virtio-net",
	.init_fds = netbe_init_fds,
	.legacy_config = netbe_legacy_config,
	.validate_hotplug_request = netbe_validate_hotplug_request
};

DATA_SET(pci_devinfo, e1000_info);
DATA_SET(pci_devinfo, virtio_net_info);
