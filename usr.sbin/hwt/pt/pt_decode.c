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
#include <amd64/pt/pt.h>
#include <libipt/intel-pt.h>

#include "../hwt.h"
#include "../hwt_pt.h"
#include "../hwt_fmt.h"

#include "pt_fmt.h"

static int
pt_decode_chunk_insn(struct trace_context *tc, struct pt_dec_ctx *dctx,
    uint64_t start, size_t len, uint64_t *processed)
{
	int ret;
	int error;
	uint64_t offs;
	struct pt_insn insn;
	struct pt_event event;
	struct pt_config *cfg;
	struct pt_insn_decoder *dec;

	error = 0;
	offs = start;
	dec = dctx->dec;
	/* Set decoder to current offset. */
	cfg = __DECONST(struct pt_config *, pt_insn_get_config(dec));
	cfg->end = (uint8_t *)dctx->tracebuf + (start + len);
	ret = pt_insn_sync_set(dec, start);
	do {
		/* Process any pending events. */
		while (ret & pts_event_pending) {
			ret = pt_insn_event(dec, &event, sizeof(event));
			pt_insn_get_offset(dec, &offs);
			pt_print_event(tc, dctx, &event, start + offs);
		}
		ret = pt_insn_next(dec, &insn, sizeof(insn));
		if (ret >= 0) {
			pt_insn_get_offset(dec, &offs);
			pt_print_insn(tc, dctx, &insn, start + offs);
			continue;
		}
		if (ret == -pte_eos)
			break;
		/* A decoding error occured - try to resync.  */
		ret = pt_insn_sync_forward(dec);
		if (ret < 0) {
			if (ret != -pte_eos) {
				printf(
				    "%s: error decoding next instruction: %s\n",
				    __func__, pt_strerror(ret));
				error = ret;
			}
			pt_insn_get_offset(dec, &offs);
			break;
		}
		pt_insn_get_offset(dec, &offs);
	} while (offs < (start + len));
	pt_insn_get_offset(dec, &offs);
	*processed = offs - start;

	return (error);
}

static int
pt_decode_generic_init(struct trace_context *tc, struct pt_dec_ctx *dctx)
{
	char filename[MAXPATHLEN];

	if (tc->filename) {
		snprintf(filename, MAXPATHLEN, "%s%d", tc->filename,
		    dctx->id);
		dctx->out = fopen(filename, "w");
		if (dctx->out == NULL) {
			printf("Could not open %s\n", filename);
			return (ENXIO);
		}
		dctx->xop = xo_create_to_file(dctx->out, XO_STYLE_TEXT,
		    XOF_WARN);
	} else {
		dctx->out = stdout;
		dctx->xop = NULL;
	}

	return (0);
}

struct pt_decode_ops pt_decode_generic_ops = {
	.init = pt_decode_generic_init,
	.decode_chunk = pt_decode_chunk_insn
};
