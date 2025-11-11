/*
 * Copyright (c) 2025 Bojan Novković <bnovkov@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _INTERNAL_H_
#define _INTERNAL_H_

#include <sys/linker_set.h>
#include <sys/nv.h>

int netbe_init_fds(nvlist_t *nvl);
bool netbe_validate_hotplug_request(nvlist_t *nvl);
#endif // _INTERNAL_H_
