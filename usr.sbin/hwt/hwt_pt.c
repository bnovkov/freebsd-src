/*-
 * Copyright (c) 2023 Bojan Novkovic  <bnovkov@freebsd.org>
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
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/cpuset.h>
#include <sys/hwt.h>
#include <sys/wait.h>
#include <sys/sysctl.h>
#include <sys/event.h>

#include <err.h>
#include <stdio.h>
#include <string.h>

#include <libxo/xo.h>

#include <libipt/intel-pt.h>

#include "hwt.h"
#include "hwt_pt.h"

#define pt_perror(errcode) pt_errstr(pt_errcode((errcode)))

static int
hwt_pt_init(struct trace_context *tc, struct pt_packet_decoder **decoder)
{
  //	int cpu_id;
	int error;
  struct pt_packet_decoder *dec;
  struct pt_config config;
	struct kevent event;

  if(tc->raw == 0){
    memset(&config, 0, sizeof(config));
    config.size = sizeof(config);
    config.begin = tc->base;
    config.end = (uint8_t*)tc->base + tc->bufsize;
    //config.cpu = cpu_id;

    dec = pt_pkt_alloc_decoder(&config);
    if (!dec)
      //pt_strreror(errcode);?
      return (-1);

    error = pt_pkt_sync_forward(dec);
    if (error < 0){
      //        <handle error>(error);
      return error;
    }

    *decoder = dec;
  } else {
    /* No decoder needed, just a file for raw data. */
    tc->raw_f = fopen(tc->filename, "w");
    if (tc->raw_f == NULL) {
      printf("could not open file %s\n", tc->filename);
      return (ENXIO);
    }
  }

  tc->kqueue_fd = kqueue();
	if (tc->kqueue_fd == -1){
    printf("%s:  kqueue() failed\n", __func__);
		return -1;
  }

	EV_SET(&event, HWT_PT_BUF_RDY_EV, EVFILT_USER, EV_ADD | EV_CLEAR, NOTE_FFCOPY, 0, NULL);

	error = kevent(tc->kqueue_fd, &event, 1, NULL, 0, NULL);
	if (error == -1)
    errx(EXIT_FAILURE, "kevent");
	if (event.flags & EV_ERROR)
		errx(EXIT_FAILURE, "Event error: %s", strerror(event.data));

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

  if(tc->nranges){
    /* IP range filtering. */
    config->nranges = tc->nranges;
    for (i = 0; i < tc->nranges; i++) {
      config->ip_ranges[i].start = tc->addr_ranges[i*2];
      config->ip_ranges[i].end = tc->addr_ranges[i*2 + 1];
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

#if 0
static int
hwt_pt_print_packet(struct trace_context *tc __unused, struct pt_packet *pkt)
{
  int error = 0;

  switch (pkt->type) {
  default:
    printf("%s: unknown packet type encountered: %d\n", __func__, pkt->type);
    error = -1;
  }
  return (error);
}
#endif

static int
hwt_pt_decode_chunk(struct trace_context *tc __unused, size_t offs __unused, size_t len __unused, uint32_t *processed __unused){
  int error = -1;
#if 0
  struct pt_packet packet;

  pt_packet_sync_set(decoder, offset);

  while(1) {
    error = pt_pkt_get_offset(decoder, &offset);
    if (error < 0){
       diag("error getting offset", offset, error);
       break;
    }

    error = pt_pkt_next(decoder, &packet, sizeof(packet));
    if (error < 0) {
      if (error == -pte_eos){
        error = 0;
      }else {
        diag("error decoding packet", offset, error);
      }
      break;
    }

    error = hwt_pt_print_packet(offset, &packet);
    if (error < 0){
      printf("Error while processing packet: %s\n" );
      break;
    }
  }
#endif

  return (error);
}

/*
 * Dumps raw packet bytes into tc->raw_f.
 */
static int
hwt_pt_dump_chunk(struct trace_context *tc, size_t offs, size_t len, uint32_t *processed){

	void *base;

  base = (void *)((uintptr_t)tc->base + (uintptr_t)offs);
  fwrite(base, len, 1, tc->raw_f);
	fflush(tc->raw_f);

  *processed = len;

  return (0);
}

static int
pt_process_chunk(struct trace_context *tc, size_t offs, size_t len, uint32_t *processed){

  if(tc->raw){
    return hwt_pt_dump_chunk(tc, offs, len, processed);
  } else {
    return hwt_pt_decode_chunk(tc, offs, len, processed);
  }
}

static int
hwt_pt_process(struct trace_context *tc)
{
	size_t curoff, newoff;
  size_t totals;
  int error;
	int len;//, ncpu;
	uint32_t processed;
	struct pt_packet_decoder *dec;
	struct kevent tevent;

	xo_open_container("trace");
	xo_open_list("entries");

  //	ncpu = hwt_ncpu();

	error = hwt_pt_init(tc, &dec);
	if (error)
		return (error);

	error = hwt_get_offs(tc, &newoff);
	if (error) {
		printf("%s: cant get offset\n", __func__);
		return (-1);
	}

	printf("Decoder started. Press ctrl+c to stop.\n");

  curoff = 0;
	processed = 0;
	totals = 0;
	len = newoff;

	pt_process_chunk(tc, curoff, len, &processed);
	curoff += processed;
	totals += processed;

	while (1) {

		error = kevent(tc->kqueue_fd, NULL, 0, &tevent, 1, NULL);
		if (error == -1)
			err(EXIT_FAILURE, "kevent wait");

    /* TODO: MD "cookie" pointer in tc */
    /* TODO: pass buffer layout through MD cookie */
    newoff = tevent.data;
		if (newoff == curoff) {
			if (tc->terminate)
				break;
		} else if (newoff > curoff) {
			/* New entries in the trace buffer. */
			len = newoff - curoff;
			if(pt_process_chunk(tc, curoff, len, &processed)){
        break;
      }
			curoff += processed;
			totals += processed;

		} else if (newoff < curoff) {
			/* New entries in the trace buffer. Buffer wrapped. */
			len = tc->bufsize - curoff;
			if(pt_process_chunk(tc, curoff, len, &processed)){
        break;
      }
			curoff += processed;
			totals += processed;

			curoff = 0;
			len = newoff;
			if(pt_process_chunk(tc, curoff, len, &processed)){
        break;
      }
			curoff += processed;
			totals += processed;
		}
	}

	printf("\nBytes processed: %ld\n", totals);

	xo_close_list("file");
	xo_close_container("wc");
	if (xo_finish() < 0)
		xo_err(EXIT_FAILURE, "stdout");

	return (0);
}

struct trace_dev_methods pt_methods = {
	.process = hwt_pt_process,
	.set_config = hwt_pt_set_config,
};

