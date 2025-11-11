/*
 * Copyright (c) 2025 Bojan Novković <bnovkov@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _LIBBHYVE_PCI_H_
#define _LIBBHYVE_PCI_H_

#include <sys/nv.h>

#define BHYVE_RUN_DIR "/var/run/bhyve/"

/*
 * PCI routines.
 */
int pci_init_fds(nvlist_t *nvl, const char *device);
int pci_parse_config(nvlist_t *nvl, const char *device, const char *config);
int pci_parse_legacy_config(nvlist_t *nvl, const char *opt);
bool pci_validate_hotplug_request(nvlist_t *nvl, const char *device);
#endif /* _LIBBHYVE_PCI_H_ */
