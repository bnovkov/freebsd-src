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
#include <sys/hwt.h>
#include <sys/hwt_record.h>
#include <sys/tree.h>

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <libipt/intel-pt.h>
#include <libxo/xo.h>

#include "../hwt.h"
#include "../hwt_fmt.h"
#include "../hwt_pt.h"

#include "pt_fmt.h"

void
pt_print_insn(struct trace_context *tc, struct pt_dec_ctx *dctx,
    struct pt_insn *insn, uint64_t offs)
{
	xo_open_instance("entry");
	hwt_fmt_print_generic(tc, dctx->xop, dctx->id, insn->ip, offs);

	xo_emit_h(dctx->xop, "\n");
	xo_close_instance("entry");
}

void
pt_print_event(struct trace_context *tc, struct pt_dec_ctx *dctx,
    struct pt_event *ev, uint64_t offs)
{
	uint64_t ip;
	const char* evname;

	if (!HWT_FMT_SHOULD_PRINT_COLS(tc->fmt,
	    HWT_FMT_EV_TYPE | HWT_FMT_EV_PAYLOAD))
		return;

	switch (ev->type) {
	case ptev_enabled:
		evname = "trace_start";
		ip = ev->variant.enabled.ip;
		break;
	case ptev_disabled:
		evname = "trace_stop";
		ip = ev->variant.disabled.ip;
		break;
	default:
		evname = "?";
		ip = 0;
		break;
	}

	xo_open_instance("entry");
	hwt_fmt_print_generic(tc, dctx->xop, dctx->id, ip, offs);

	if (HWT_FMT_SHOULD_PRINT(tc->fmt, EV_TYPE))
		xo_emit_h(dctx->xop, "{:event_type}", evname);
	if (HWT_FMT_SHOULD_PRINT(tc->fmt, EV_PAYLOAD))
		xo_emit_h(dctx->xop, "{:event_payload/+0x%lx/%ju}", ip);

	xo_emit_h(dctx->xop, "\n");
	xo_close_instance("entry");
}
