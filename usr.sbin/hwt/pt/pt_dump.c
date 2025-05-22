/*-
 * Copyright (c) 2025 Bojan Novković  <bnovkov@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <amd64/pt/pt.h>
#include <sys/errno.h>
#include <sys/hwt.h>
#include <sys/hwt_record.h>
#include <sys/param.h>
#include <sys/tree.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <libxo/xo.h>
#include <libipt/intel-pt.h>

#include "../libpmcstat_stubs.h"
#include <libpmcstat.h>

#include "../hwt.h"
#include "../hwt_pt.h"

static int
pt_dump_init(struct trace_context *tc, struct pt_dec_ctx *dctx)
{
	char filename[MAXPATHLEN];

	/* No decoder needed, just a file for raw data. */
	snprintf(filename, MAXPATHLEN, "%s%d", tc->filename,
	    dctx->id);
	dctx->out = fopen(filename, "w");
	if (dctx->out == NULL) {
		printf("%s: could not open file %s\n", __func__,
		    filename);
		return (ENXIO);
	}
	return (0);
}

/*
 * Dumps raw packet bytes.
 */
static int
pt_dump_chunk(struct trace_context *tc __unused, struct pt_dec_ctx *dctx,
    uint64_t offs, size_t len, uint64_t *processed)
{
	void *base;

	base = (void *)((uintptr_t)dctx->tracebuf + (uintptr_t)offs);
	fwrite(base, len, 1, dctx->out);
	fflush(dctx->out);
	*processed = len;

	return (0);
}

struct pt_decode_ops pt_dump_ops = {
	.init = pt_dump_init,
	.decode_chunk = pt_dump_chunk
};
