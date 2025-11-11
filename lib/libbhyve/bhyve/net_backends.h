/*
 * Copyright (c) 2025 Bojan Novković <bnovkov@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _LIBBHYVE_NET_H_
#define _LIBBHYVE_NET_H_

#include <sys/nv.h>

int netbe_legacy_config(nvlist_t *nvl, const char *opts);
#endif /* _LIBBHYVE_NET_H_ */
