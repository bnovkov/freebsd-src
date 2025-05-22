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

#ifndef _HWT_FMT_H_
#define _HWT_FMT_H_

#include <libxo/xo.h>
enum hwt_fmt_column {
	HWT_FMT_OFFSET = 0x1,
	HWT_FMT_ID = 0x2,
	HWT_FMT_IMAGE_NAME = 0x4,
	HWT_FMT_SYM_NAME = 0x8,
	HWT_FMT_PC = 0x10,
	HWT_FMT_EV_TYPE = 0x20,
	HWT_FMT_EV_PAYLOAD = 0x40,
	HWT_FMT_DISAS = 0x80,
};

#define HWT_FMT_SHOULD_PRINT_COLS(flags, cols) ((flags & (cols)) != 0)
#define HWT_FMT_SHOULD_PRINT(flags, col) ((flags & HWT_FMT_##col) != 0)
#define HWT_FMT_DEFAULT_COLS (HWT_FMT_OFFSET | HWT_FMT_ID | HWT_FMT_SYM_NAME | \
	    HWT_FMT_PC)

struct trace_context;
void hwt_fmt_print_generic(struct trace_context *tc, xo_handle_t *xop, int id,
    uint64_t pc, uint64_t offs);

enum hwt_fmt_column hwt_fmt_parse_cols(const char *args);
#endif /* _HWT_FMT_H_ */
