/*-
 * Copyright (c) 2023 Bojan Novković  <bnovkov@freebsd.org>
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

#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/errno.h>
#include <sys/event.h>
#include <sys/hwt.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <err.h>
#include <libipt/intel-pt.h>
#include <libxo/xo.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "hwt.h"
#include "hwt_pt.h"
#include "sys/_stdint.h"
#include "sys/systm.h"
#include "sys/types.h"

#define pt_strerror(errcode) pt_errstr(pt_errcode((errcode)))

/*
 * Decoder per-cpu state.
 */
static struct hwt_pt_cpu {
	size_t curoff;
	void *tracebuf;
	struct pt_packet_decoder *dec;
} *hwt_pt_pcpu;

static int
hwt_pt_init(struct trace_context *tc)
{

	hwt_pt_pcpu = calloc(hwt_ncpu(), sizeof(struct hwt_pt_cpu));
	if (!hwt_pt_pcpu) {
		printf("%s: failed to allocate decoder\n", __func__);
		return (-1);
	}
	if (tc->raw) {
		/* No decoder needed, just a file for raw data. */
		tc->raw_f = fopen(tc->filename, "w");
		if (tc->raw_f == NULL) {
			printf("%s: could not open file %s\n", __func__,
			    tc->filename);
			return (ENXIO);
		}
	}

	return (0);
}

static int
hwt_pt_mmap(struct trace_context *tc)
{
	int error;
	int cpu_id, tc_fd = -1, _fd;
	struct hwt_pt_cpu *cpu;
	struct pt_config config;

	if (tc->mode == HWT_MODE_CPU) {
		CPU_FOREACH_ISSET (cpu_id, &tc->cpu_map) {
			cpu = &hwt_pt_pcpu[cpu_id];

			error = hwt_map_tracebuf(tc, cpu_id,
			    tc_fd == -1 ? &tc_fd : &_fd, &cpu->tracebuf);
			if (error != 0) {
				printf(
				    "%s: failed to map tracing buffer for cpu %d: %s\n",
				    __func__, cpu_id, strerror(errno));
				return (-1);
			}

			if (!tc->raw) {
				memset(&config, 0, sizeof(config));
				config.size = sizeof(config);
				config.begin = cpu->tracebuf;
				config.end = (uint8_t *)cpu->tracebuf +
				    tc->bufsize;

				cpu->dec = pt_pkt_alloc_decoder(&config);
				if (cpu->dec == NULL) {
					printf(
					    "%s: failed to allocate PT decoder for cpu %d\n",
					    __func__, cpu_id);
					return (-1);
				}
			}
		}
	} else {
		return (-1);
	}

	/* thr_fd is used to issue ioctls which control all cores
	 * use fd to the first cpu for this (thread is always 0) */
	assert(tc_fd != -1);
	tc->thr_fd = tc_fd;

	return (0);
}

static int
hwt_pt_set_config(struct trace_context *tc)
{
	struct hwt_set_config sconf;
	struct pt_cpu_config *config;
	int i, error;
	uint64_t rtit_ctl = 0;

	config = calloc(1, sizeof(struct pt_cpu_config));
	/* Fill config */
	if (tc->mode == HWT_MODE_THREAD)
		rtit_ctl |= RTIT_CTL_USER;
	else
		rtit_ctl |= RTIT_CTL_OS;

	if (tc->nranges) {
		/* IP range filtering. */
		config->nranges = tc->nranges;
		for (i = 0; i < tc->nranges; i++) {
			config->ip_ranges[i].start = tc->addr_ranges[i * 2];
			config->ip_ranges[i].end = tc->addr_ranges[i * 2 + 1];
		}
	}

	rtit_ctl |= RTIT_CTL_BRANCHEN;

	config->rtit_ctl = rtit_ctl;
	tc->config = config;

	sconf.config = config;
	sconf.config_size = sizeof(struct pt_config);
	sconf.config_version = 1;
	sconf.pause_on_mmap = tc->suspend_on_mmap ? 1 : 0;

	error = ioctl(tc->thr_fd, HWT_IOC_SET_CONFIG, &sconf);

	return (error);
}

static void
hwt_pt_print_tnt(const struct pt_packet_tnt *packet)
{
	uint64_t tnt;
	uint8_t bits;

	bits = packet->bit_size;
	tnt = packet->payload;

	while (--bits)
		putc(tnt & (1ull << (bits - 1)) ? '!' : '.', stdout);
}

static void
hwt_pt_print_mode(const struct pt_packet_mode *pkt)
{
	enum pt_exec_mode mode;

	switch (pkt->leaf) {
	case pt_mol_exec: {
		printf(".exec: ");
		mode = pt_get_exec_mode(&pkt->bits.exec);
		switch (mode) {
		case ptem_64bit:
			printf("64-bit");
			break;
		case ptem_32bit:
			printf("32-bit");
			break;
		case ptem_16bit:
			printf("16-bit");
			break;
		default:
			printf("unknown");
			break;
		}
		break;
	}
	case pt_mol_tsx:
		printf(".tsx");
		break;
	}
}

static int
hwt_pt_print_packet(const struct pt_packet *pkt)
{

	switch (pkt->type) {
	case ppt_unknown:
		printf("<unknown>");
		break;
	case ppt_invalid:
		printf("<invalid>");
		break;
	case ppt_tnt_8:
		printf("tnt.8\n");
		hwt_pt_print_tnt(&pkt->payload.tnt);
		break;
	case ppt_tnt_64:
		printf("tnt.64\n");
		hwt_pt_print_tnt(&pkt->payload.tnt);
		break;
	case ppt_mode:
		printf("mode");
		hwt_pt_print_mode(&pkt->payload.mode);
		break;
	case ppt_pip:
		printf("pip: cr3 %p", (void *)pkt->payload.pip.cr3);
		break;
	case ppt_vmcs:
		printf("vmcs: %p", (void *)pkt->payload.vmcs.base);
		break;
	case ppt_cbr:
		printf("cbr: ratio %u", pkt->payload.cbr.ratio);
		break;
	case ppt_tip_pge:
		printf("pge: TRACE START @%p", (void *)pkt->payload.ip.ip);
		break;
	case ppt_tip_pgd:
		printf("pgd: TRACE STOP @%p", (void *)pkt->payload.ip.ip);
		break;
	case ppt_fup:
		printf("fup: @%p", (void *)pkt->payload.ip.ip);
		break;
	case ppt_pad:
	case ppt_psb:
	case ppt_psbend:
		/* Ignore */
		return (0);
	default:
		printf("%s: unknown packet type encountered: %d\n", __func__,
		    pkt->type);
		return (-1);
	}
	printf("\n");

	return (0);
}

static int
hwt_pt_decode_chunk(struct pt_packet_decoder *dec, uint64_t start, size_t len,
    uint64_t *processed)
{
	int error = 0;
	uint64_t prevoffs, offs;
	int ret;
	struct pt_packet packet;

	printf("%s: start %zu, len %zu\n", __func__, start, len);

	offs = prevoffs = start;
	/* Set decoder to current offset. */
	pt_pkt_sync_set(dec, start);

	do {
		ret = pt_pkt_next(dec, &packet, sizeof(packet));
		if (ret < 0) {
			if (ret == -pte_eos) {
				/* Restore previous offset */
				pt_pkt_sync_set(dec, prevoffs);
				offs = prevoffs;
			} else {
				error = ret;
				printf("%s: error decoding next packet: %s\n",
				    __func__, pt_strerror(error));
			}
			break;
		}
		error = hwt_pt_print_packet(&packet);
		if (error < 0) {
			printf("%s: error while processing packet: %s\n",
			    __func__, pt_strerror(error));
			break;
		}

		prevoffs = offs;
		offs += ret;

		if (offs > (start + len))
			break;
	} while (1);
	*processed = offs - start;

	return (error);
}

/*
 * Dumps raw packet bytes into tc->raw_f.
 */
static int
hwt_pt_dump_chunk(struct hwt_pt_cpu *cpu, FILE *raw_f, uint64_t offs,
    size_t len, uint64_t *processed)
{
	void *base;

	base = (void *)((uintptr_t)cpu->tracebuf + (uintptr_t)offs);
	fwrite(base, len, 1, raw_f);
	fflush(raw_f);

	*processed = len;

	return (0);
}

static int
pt_process_chunk(struct trace_context *tc, struct hwt_pt_cpu *cpu,
    uint64_t offs, size_t len, uint64_t *processed)
{
	if (tc->raw) {
		return hwt_pt_dump_chunk(cpu, tc->raw_f, offs, len, processed);
	} else {
		return hwt_pt_decode_chunk(cpu->dec, offs, len, processed);
	}
}

static int
hwt_pt_process(struct trace_context *tc)
{
	uint64_t curoff, newoff;
	size_t totals;
	int error;
	int len, cpu_id = 0; // assume cpu_id == 0 for now
	uint64_t processed;
	struct hwt_pt_cpu *cpu;

	xo_open_container("trace");
	xo_open_list("entries");

	printf("Decoder started. Press ctrl+c to stop.\n");

	curoff = 0;
	processed = 0;
	totals = 0;
	len = 0;

	while (1) {
		printf("%s: fetching new offset\n", __func__);
		error = hwt_get_offs(tc, &newoff);
		if (error < 0)
			err(EXIT_FAILURE, "hwt_get_offs");
		printf("%s: new offset %zu\n", __func__, newoff);

		cpu = &hwt_pt_pcpu[cpu_id];
		curoff = cpu->curoff;
		if (newoff == curoff) {
			if (tc->terminate)
				break;
		} else if (newoff > curoff) {
			/* New entries in the trace buffer. */
			len = newoff - curoff;
			if (pt_process_chunk(tc, cpu, curoff, len,
				&processed)) {
				break;
			}
			curoff += processed;
			totals += processed;

		} else if (newoff < curoff) {
			/* New entries in the trace buffer. Buffer wrapped. */
			len = tc->bufsize - curoff;
			if (pt_process_chunk(tc, cpu, curoff, len,
				&processed)) {
				break;
			}
			curoff += processed;
			totals += processed;

			curoff = 0;
			len = newoff;
			if (pt_process_chunk(tc, cpu, curoff, len,
				&processed)) {
				break;
			}
			curoff += processed;
			totals += processed;
		}
		/* Save current offset for cpu */
		cpu->curoff = curoff;
	}

	printf("\nBytes processed: %ld\n", totals);

	xo_close_list("file");
	xo_close_container("wc");
	if (xo_finish() < 0)
		xo_err(EXIT_FAILURE, "stdout");

	return (0);
}

struct trace_dev_methods pt_methods = {
	.init = hwt_pt_init,
	.mmap = hwt_pt_mmap,
	.process = hwt_pt_process,
	.set_config = hwt_pt_set_config,
};
