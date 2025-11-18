/*
 *
 * Copyright (c) 2019 Vincenzo Maffione <vmaffione@FreeBSD.org>
 * Copyright (c) 2023 Mark Johnston <markj@FreeBSD.org>
 * Copyright (c) 2025 Bojan Novković <bnovkov@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/nv.h>
#include <sys/nv_namespace.h>
#include <sys/socket.h>
#include <sys/procdesc.h>

#include <net/if.h>
#include <net/netmap.h>
#include <net/netmap_virt.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netgraph.h>
#include <spawn.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "bhyve/config.h"
#include "bhyve/net_backends.h"
#include "bhyve/pci.h"
#include "internal.h"

struct netbe_info {
	const char *prefix;
	int (*init_fds)(nvlist_t *);
	bool (*validate_hotplug_request)(nvlist_t *);
};

extern char **environ;

static int
slirp_init_fds(nvlist_t *nvl)
{
	int error;
	pid_t child;
	int child_pd;
	const char **argv;
	char sockname[32];
	int sockpair_fds[2];
	posix_spawnattr_t attr;
	posix_spawn_file_actions_t fa;

	error = socketpair(PF_LOCAL, SOCK_SEQPACKET | SOCK_NONBLOCK, 0,
	    sockpair_fds);
	if (error != 0) {
		nvlist_add_stringf(nvl, "error", "Unable to create pipe: %s",
		    strerror(errno));
		return (error);
	}

	/*
	 * The child will exit once its connection goes away, so make sure only
	 * one end is inherited by the child.
	 */
	if (posix_spawn_file_actions_init(&fa) != 0) {
		nvlist_add_string(nvl, "error",
		    "posix_spawn_file_actions_init");
		return (error);
	}
	if (posix_spawn_file_actions_addclose(&fa, sockpair_fds[0]) != 0) {
		nvlist_add_string(nvl, "error",
		    "posix_spawn_file_actions_addclose");
		posix_spawn_file_actions_destroy(&fa);
		return (error);
	}
	if (posix_spawnattr_init(&attr) != 0) {
		nvlist_add_string(nvl, "error", "posix_spawnattr_init");
		posix_spawn_file_actions_destroy(&fa);
		return (error);
	}
	if (posix_spawnattr_setprocdescp_np(&attr, &child_pd, PD_CLOEXEC) != 0) {
		nvlist_add_string(nvl, "error",
		    "posix_spawnattr_setprocdescp_np");
		posix_spawn_file_actions_destroy(&fa);
		posix_spawnattr_destroy(&attr);
		return (error);
	}
	(void)snprintf(sockname, sizeof(sockname), "%d", sockpair_fds[1]);
	argv = (const char *[]){
	    "/usr/libexec/bhyve-slirp-helper", "-S", sockname, NULL
	};
	child_pd = -1;
	error = posix_spawn(&child, "/usr/libexec/bhyve-slirp-helper",
	    &fa, &attr, __DECONST(char **, argv), environ);
	posix_spawn_file_actions_destroy(&fa);
	posix_spawnattr_destroy(&attr);
	if (error != 0) {
		nvlist_add_stringf(nvl, "error", "posix_spawn(bhyve-slirp-helper): %s",
		    strerror(error));
		return (error);
	}
	assert(child_pd != -1);

	nvlist_add_descriptor_array(nvl, "sockpair", sockpair_fds,
	    nitems(sockpair_fds));
	nvlist_add_descriptor(nvl, "helper_pd", child_pd);

	return (0);
}

static bool
slirp_validate_hotplug_request(nvlist_t *nvl)
{
	if (!nvlist_exists_descriptor_array(nvl, "sockpair")) {
		nvlist_add_string(nvl, "error",
		    "missing socket descriptor pair");
		return (false);
	}

	if (!nvlist_exists_descriptor(nvl, "helper_pd")) {
		nvlist_add_string(nvl, "error",
		    "missing slirp helper process descriptor");
		return (false);
	}

	return (true);
}

static int
tap_init_fds(nvlist_t *nvl)
{
	int fd;
	char tbuf[80];
	const char *devname;

	if (!nvlist_exists_string(nvl, "backend")) {
		nvlist_add_string(nvl, "error", "missing backend parameter");
		return (-1);
	}

	devname = nvlist_get_string(nvl, "backend");
	strcpy(tbuf, "/dev/");
	strlcat(tbuf, devname, sizeof(tbuf));
	fd = open(tbuf, O_RDWR);
	if (fd == -1) {
		nvlist_add_stringf(nvl, "error",
		    "open of tap device %s failed: %s", tbuf, strerror(errno));
		return (-1);
	}
	nvlist_move_descriptor(nvl, "devfd", fd);

	return (0);
}

static bool
tap_validate_hotplug_request(nvlist_t *nvl)
{
	if (!nvlist_exists_descriptor(nvl, "devfd")) {
		nvlist_add_string(nvl, "error",
		    "missing tap device file descriptor");
		return (false);
	}
	return (true);
}

static int
ng_init_fds(nvlist_t *nvl)
{
	int csp, dsp;
	const char *nodename;

	if (!nvlist_exists_string(nvl, "socket")) {
		nvlist_add_string(nvl, "error", "missing socket path");
		return (-1);
	}
	nodename = nvlist_get_string(nvl, "socket");
	if (NgMkSockNode(nodename, &csp, &dsp) < 0) {
		nvlist_add_stringf(nvl, "error", "can't get Netgraph sockets");
		return (-1);
	}

	nvlist_move_descriptor(nvl, "csp", csp);
	nvlist_move_descriptor(nvl, "dsp", dsp);

	return (0);
}

static bool
ng_validate_hotplug_request(nvlist_t *nvl)
{
	if (!nvlist_exists_descriptor(nvl, "csp")) {
		nvlist_add_string(nvl, "error",
		    "missing control socket descriptor");
		return (false);
	}
	if (!nvlist_exists_descriptor(nvl, "dsp")) {
		nvlist_add_string(nvl, "error",
		    "missing data socket descriptor");
		return (false);
	}

	return (true);
}

static int
netmap_init_fds(nvlist_t *nvl)
{
	struct nm_desc *nmd;
	const char *devname;

	if (!nvlist_exists_string(nvl, "backend")) {
		nvlist_add_string(nvl, "error", "missing backend parameter");
		return (-1);
	}
	devname = nvlist_get_string(nvl, "backend");
	nmd = nm_open(devname, NULL, NETMAP_NO_TX_POLL, NULL);
	if (nmd == NULL) {
		nvlist_add_stringf(nvl, "error",
		    "Unable to nm_open(): interface '%s', errno (%s)", devname,
		    strerror(errno));
		return (-1);
	}
	nvlist_move_binary(nvl, "nm_desc", nmd, sizeof(*nmd));

	return (0);
}

static bool
netmap_validate_hotplug_request(nvlist_t *nvl)
{
	size_t size;
	struct nm_desc *nmd;

	if (!nvlist_exists_binary(nvl, "nm_desc")) {
		nvlist_add_string(nvl, "error",
		    "missing netmap descriptor structure");
		return (false);
	}

	(void)nvlist_get_binary(nvl, "nm_desc", &size);
	if (size != sizeof(*nmd)) {
		nvlist_add_string(nvl, "error",
		    "mismatched netmap descriptor structure size");
		return (false);
	}

	return (true);
}

static struct netbe_info netbe_tap = {
	.prefix = "tap",
	.init_fds = tap_init_fds,
	.validate_hotplug_request = tap_validate_hotplug_request
};

static struct netbe_info netbe_ngd = {
	.prefix = "ngd",
	.init_fds = tap_init_fds,
	.validate_hotplug_request = tap_validate_hotplug_request
};

static struct netbe_info netbe_netmap = {
	.prefix = "netmap",
	.init_fds = netmap_init_fds,
	.validate_hotplug_request = netmap_validate_hotplug_request
};

static struct netbe_info netbe_netgraph = {
	.prefix = "netgraph",
	.init_fds = ng_init_fds,
	.validate_hotplug_request = ng_validate_hotplug_request
};

static struct netbe_info netbe_slirp = {
	.prefix = "slirp",
	.init_fds = slirp_init_fds,
	.validate_hotplug_request = slirp_validate_hotplug_request
};

SET_DECLARE(net_backends_info, struct netbe_info);
DATA_SET(net_backends_info, netbe_netgraph);
DATA_SET(net_backends_info, netbe_slirp);
DATA_SET(net_backends_info, netbe_netmap);
DATA_SET(net_backends_info, netbe_tap);
DATA_SET(net_backends_info, netbe_ngd);

static struct netbe_info *
find_netbe_info(const char *backend)
{
	struct netbe_info **nbe;

	SET_FOREACH(nbe, net_backends_info) {
		if (strncmp(backend, (*nbe)->prefix,
		    strlen((*nbe)->prefix)) == 0) {
			return (*nbe);
		}
	}
	return (NULL);
}

int
netbe_init_fds(nvlist_t *nvl)
{
	const char *backend;
	struct netbe_info *nbi;

	if (!nvlist_exists_string(nvl, "backend")) {
		nvlist_add_string(nvl, "error", "missing backend argument");
		return (-1);
	}
	backend = nvlist_get_string(nvl, "backend");
	nbi = find_netbe_info(backend);
	if (nbi == NULL) {
		nvlist_add_stringf(nvl, "error", "unknown backend '%s'",
		    backend);
		return (-1);
	}

	if (nbi->init_fds == NULL)
		return (0);

	return (nbi->init_fds(nvl));
}

int
netbe_legacy_config(nvlist_t *nvl, const char *opts)
{
	char *backend, *cp;

	if (opts == NULL)
		return (0);

	cp = strchr(opts, ',');
	if (cp == NULL) {
		set_config_value_node(nvl, "backend", opts);
		return (0);
	}
	backend = strndup(opts, cp - opts);
	set_config_value_node(nvl, "backend", backend);
	free(backend);
	return (pci_parse_legacy_config(nvl, cp + 1));
}

bool
netbe_validate_hotplug_request(nvlist_t *nvl)
{
	const char *backend;
	struct netbe_info *nbi;

	if (!nvlist_exists_string(nvl, "backend")) {
		nvlist_add_string(nvl, "error", "missing backend argument");
		return (-1);
	}
	backend = nvlist_get_string(nvl, "backend");
	nbi = find_netbe_info(backend);

	if (nbi == NULL || nbi->validate_hotplug_request == NULL)
		return (0);

	return (nbi->validate_hotplug_request(nvl));
}
