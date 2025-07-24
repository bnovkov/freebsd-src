/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Arm Ltd
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

/*
 * Arm Statistical Profiling Extension (SPE)
 *
 * Note: this userspace tool currently has basic functionality in terms of
 * configuration + filtering. It can only dump raw SPE records via the `-w
 * filename` command line option. See arm_spe_config for currently available
 * config however these are not yet available via command line options.
 *
 * There is currently no inbuilt decoder but the raw SPE records can be decoded
 * with the following tool:
 *
 *     https://gitlab.arm.com/telemetry-solution/telemetry-solution/-/tree/main/tools/spe_parser
 *
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
#include <sysexits.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>

#include "hwt.h"
#include "hwt_spe.h"
#include "arm64/spe/arm_spe.h"

#define	HWT_SPE_DEBUG
#undef	HWT_SPE_DEBUG

#ifdef	HWT_SPE_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static struct arm_spe_mmap *spe_mmap;
static int kq_fd;

#ifdef HWT_SPE_DEBUG
static void hex_dump(uint8_t *buf, size_t len)
{
    size_t i;

    printf("--------------------------------------------------------------\n");
    for (i = 0; i < len; ++i) {
        if (i % 8 == 0) {
            printf(" ");
        }
        if (i % 16 == 0) {
            if (i != 0) {
                printf("\r\n");
            }
            printf("\t");
        }
        printf("%02X ", buf[i]);
    }
    printf("\r\n");
}
#else
static void hex_dump(uint8_t *buf __unused, size_t len __unused) {}
#endif

static int
hwt_map_memory(struct trace_context *tc, int id, int *fd, void **addr)
{
	char filename[32];

	sprintf(filename, "/dev/hwt_%d_%d", tc->ident, id);

	*fd = open(filename, O_RDONLY);
	if (*fd < 0) {
		printf("Can't open %s\n", filename);
		return (-1);
	}

	*addr = mmap(NULL, tc->bufsize, PROT_READ, MAP_SHARED, *fd, 0);
	if (*addr == MAP_FAILED) {
		printf("mmap failed: err %d\n", errno);
		return (-1);
	}

	return (0);
}

static int
hwt_spe_mmap(struct trace_context *tc,
    struct hwt_record_user_entry *entry __unused)
{
	int error, cpu_id, i=0;

	spe_mmap = malloc(sizeof(struct arm_spe_mmap));
	if (spe_mmap == NULL)
		return (ENOMEM);

	if (tc->mode == HWT_MODE_CPU)
		spe_mmap->n = CPU_COUNT(&tc->cpu_map);
	else /* HWT_MODE_THREAD */
		spe_mmap->n = 1;

	spe_mmap->m = CPU_FLS(&tc->cpu_map); /* Highest id in cpu_map + 1 */
	/* Maintain a mapping between cpu_id + idx in bufs[idx] */
	spe_mmap->idx = malloc(sizeof(uint16_t) * spe_mmap->m);
	spe_mmap->bufs = malloc(sizeof(void *) * spe_mmap->n);
	spe_mmap->fds = malloc(sizeof(int) * spe_mmap->n);
	if (spe_mmap->bufs == NULL || spe_mmap->fds == NULL)
		return (ENOMEM);
	dprintf("spe_mmap->bufs:%p, spe_mmap->n:%d\n", spe_mmap->bufs, spe_mmap->n);

	if (tc->mode == HWT_MODE_CPU) {
		CPU_FOREACH_ISSET(cpu_id, &tc->cpu_map) {
			error = hwt_map_memory(tc, cpu_id,
			    &spe_mmap->fds[i], &spe_mmap->bufs[i]);
			dprintf("cpu_id:%d &spe_mmap->bufs[%d]:%p value:%p\n", cpu_id, i, &spe_mmap->bufs[i], spe_mmap->bufs[i]);
			if (error)
				return error;
			spe_mmap->idx[cpu_id] = i;
			i++;
		}
	} else { /* HWT_MODE_THREAD */
		error = hwt_map_memory(tc, 0,
		    &spe_mmap->fds[0], &spe_mmap->bufs[0]);
		if (error)
			return error;
	}

	/*
	 * thr_fd is used to issue ioctls which control all cores
	 * use fd to the first cpu for this (thread is always 0)
	 */
	tc->thr_fd = spe_mmap->fds[0];

	return (0);
}

static int
hwt_spe_init(struct trace_context *tc)
{
	struct kevent event[3];
	int ret;

	if (tc->raw) {
		/* No decoder needed, just a file for raw data. */
		tc->raw_f = fopen(tc->filename, "wb");
		if (tc->raw_f == NULL) {
			printf("%s: could not open file %s\n", __func__,
			    tc->filename);
			return (ENXIO);
		}
	} else {
		printf("error: SPE can currently only dump raw data: '-r' "
		    "flag is required with '-w filename'\n");
		return (ENOTSUP);
	}

	/*
	 * Setup kevent queue to process ARM_SPE_KQ_{...} events from:
	 *	1. kernel (e.g. buffer full event)
	 *	2. userspace signal handler
	 */
	tc->kqueue_fd = kqueue();
	if (tc->kqueue_fd == -1)
		err(EXIT_FAILURE, "kqueue() failed");

	kq_fd = tc->kqueue_fd; /* sig handler needs access to kq via global */

	EV_SET(&event[0], ARM_SPE_KQ_BUF, EVFILT_USER, EV_ADD | EV_CLEAR,
	    NOTE_FFCOPY, 0, NULL);
	EV_SET(&event[1], ARM_SPE_KQ_SHUTDOWN, EVFILT_USER, EV_ADD | EV_CLEAR,
	    NOTE_FFCOPY, 0, NULL);
	EV_SET(&event[2], ARM_SPE_KQ_SIGNAL, EVFILT_USER, EV_ADD | EV_CLEAR,
	    NOTE_FFCOPY, 0, NULL);

	ret = kevent(tc->kqueue_fd, event, 3, NULL, 0, NULL);
	if (ret == -1)
		err(EXIT_FAILURE, "kevent register");
	for (int i = 0; i < 3; i++) {
		if (event[i].flags & EV_ERROR)
			errx(EXIT_FAILURE, "Event error: %s",
			    strerror(event[i].data));
	}

	return ret;
}

static void
sighandler(const int sig_num)
{
	struct kevent kev;
	int ret;

	// TODO - handle different signals differently?
	switch (sig_num) {
	case SIGINT:
		printf("SIGINT\n"); /* ctrl+c */
		break;
	case SIGTERM:
		printf("SIGTERM\n");
		break;
	default:
		break;
	}

	/* Wake up event loop in hwt_spe_process */
	EV_SET(&kev, ARM_SPE_KQ_SIGNAL, EVFILT_USER, 0,
	    NOTE_TRIGGER | NOTE_FFCOPY, 0, NULL);
	ret = kevent(kq_fd, &kev, 1, NULL, 0, NULL);
	if (ret == -1)
		err(EXIT_FAILURE, "kevent register");
	if (kev.flags & EV_ERROR)
		errx(EXIT_FAILURE, "event error: %s", strerror(kev.data));
}

static int
hwt_spe_stop_tracing(struct trace_context *tc)
{
	int err;

	err = hwt_stop_tracing(tc);
	if (err)
		errx(EX_SOFTWARE, "failed to stop tracing, error %d\n", err);

	return err;
}

static void
hwt_spe_free(void)
{
	free(spe_mmap->idx);
	free(spe_mmap->bufs);
	free(spe_mmap->fds);
	free(spe_mmap);
}

static int
hwt_spe_get_data(struct trace_context *tc)
{

	struct hwt_bufptr_get bget;
	struct hwt_svc_buf svc_buf;
	struct arm_spe_svc_buf binfo;
	vm_offset_t buf_start = 0;
	size_t size, ret;
	uint64_t data;
	void *buf;
	int ident, idx, error;
	bool not_final;

	bget.ident = &ident;
	bget.offset = &size;
	bget.data = &data;

	/*
	 * Returns the oldest buffer that needs servicing or errno ENOENT if
	 * there are no buffers pending
	 */
	error = ioctl(tc->thr_fd, HWT_IOC_BUFPTR_GET, &bget);
	if (error) {
		if (errno == ENOENT) /* no items on queue */
			return (0);

		errx(EX_SOFTWARE, "Failed HWT_IOC_BUFPTR_GET err:%d %s\n",
		    errno, strerror(errno));
	}

	if (ident > (spe_mmap->m - 1))
		return ENXIO;
	idx = spe_mmap->idx[ident];


	/* Copy from the correct half of the ping pong buffer */
	if ((data & KQ_BUF_POS) == 0)
		buf_start = 0;
	else
		buf_start = tc->bufsize/2;

	/* TODO: once decoder is implemented, if KQ_PARTREC, discard last (partial) record */
	buf = (uint8_t *)spe_mmap->bufs[idx]+buf_start;
	hex_dump(buf, 64);
	ret = fwrite(buf, 1, size, tc->raw_f);
	if (ret < size)
		errx(EX_SOFTWARE, "failed to write to file, wrote %zu/%zu bytes\n",
		    ret, size);
	else
		tc->bytes_written += ret;

	/* Clear service buffer flag */
	binfo.ident = ident;
	binfo.buf_idx = (data & KQ_BUF_POS);
	svc_buf.data = &binfo;
	svc_buf.data_size = sizeof(binfo);
	svc_buf.data_version = 1;

	/* KQ_BUF_FINAL indicates shutdown so no need to clear service flag */
	not_final = !(data & KQ_FINAL_BUF);
	if (not_final && ioctl(tc->thr_fd, HWT_IOC_SVC_BUF, &svc_buf)) {
		errx(EX_SOFTWARE, "Failed HWT_IOC_SVC_BUF err:%d %s\n",
		    errno, strerror(errno));
	}

	return error;
}

static int
hwt_spe_process(struct trace_context *tc)
{
	struct kevent kev;
	int ret;
	struct sigaction sigact = {0};
	int nevents;
	u_int npending;

	sigact.sa_handler = sighandler;
	sigact.sa_flags = SA_RESTART;
	/* TODO: register/handle other signals */
	sigaction(SIGINT, &sigact, 0);
	sigaction(SIGHUP, &sigact, 0);
	sigaction(SIGTERM, &sigact, 0);
	sigaction(SIGQUIT, &sigact, 0);

	dprintf("%s tc->image_name:%s tc->func_name:%s tc->ident:%d\n", __func__, tc->image_name, tc->func_name, tc->ident);
	printf("Press ctrl+c to stop profiling\n");

	for (;;) {
		/* Sleep until something happens. */
		nevents = kevent(tc->kqueue_fd, NULL, 0, &kev, 1, NULL);
		if (nevents == -1 && errno != EINTR)
			err(EXIT_FAILURE, "kevent wait");
		else if (nevents == -1 && errno == EINTR)
			continue;

		dprintf("%s nevents:%d kev.fflags:%x data:%#lx\n", __func__,
		    nevents, kev.fflags, kev.data);

		if (kev.ident == ARM_SPE_KQ_SIGNAL) {
			dprintf("%s ARM_SPE_KQ_SIGNAL\n", __func__);
			ret = hwt_spe_stop_tracing(tc);
			if (ret)
				goto free;
		}
		if (kev.ident == ARM_SPE_KQ_BUF) {
			dprintf("%s ARM_SPE_KQ_BUF npending:%lu\n", __func__, kev.data);
			npending = kev.data;
			while (npending) {
				ret = hwt_spe_get_data(tc);
				if (ret) {
					printf("hwt_spe_get_data error:%d %s\n",
					    ret, strerror(errno));
					goto free;
				}
				npending--;
			}
		}
		if (kev.ident == ARM_SPE_KQ_SHUTDOWN) {
			dprintf("%s ARM_SPE_KQ_SHUTDOWN\n", __func__);
			goto free;
		}
	}

free:
	hwt_spe_free();

	if (tc->raw)
		printf("%s %lu bytes written to file %s\n", __func__,
		    tc->bytes_written, tc->filename);

	if (errno == EINTR)
		return 0;

	return ret;
}

static int
hwt_spe_set_config(struct trace_context *tc)
{
	struct hwt_set_config sconf;
	struct arm_spe_config *cfg;
	int ret;

	cfg = calloc(1, sizeof(struct arm_spe_config));
	if (cfg == NULL)
		return (ENOMEM);

	sconf.config = cfg;
	sconf.config_size = sizeof(struct arm_spe_config);
	sconf.config_version = 1;
	sconf.pause_on_mmap = tc->suspend_on_mmap ? 1 : 0;

	cfg->interval = 4096;
	cfg->level = ARM_SPE_KERNEL_AND_USER;
	cfg->ctx_field = ARM_SPE_CTX_PID;

	tc->config = cfg;

	ret = ioctl(tc->thr_fd, HWT_IOC_SET_CONFIG, &sconf);

	return ret;
}

struct trace_dev_methods spe_methods = {
	.init = hwt_spe_init,
	.mmap = hwt_spe_mmap,
	.process = hwt_spe_process,
	.set_config = hwt_spe_set_config,
};
