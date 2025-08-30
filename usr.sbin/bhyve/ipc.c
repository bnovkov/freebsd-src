#include "ipc.h"

#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#include <sys/linker_set.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>

#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif
#include <sys/ioctl.h>

#include <sys/cpuset.h>
#include <machine/vmm.h>
#include <machine/vmm_snapshot.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <pthread_np.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <vmmapi.h>

#include "bhyverun.h"
#include "debug.h"

#define BHYVE_RUN_DIR		       "/var/run/bhyve/"
#define IPC_COMMAND_FOREACH(pvar, set) SET_FOREACH(pvar, set)

SET_DECLARE(ipc_cmd_set, struct ipc_command);

static struct ipc_thread_ctx {
	struct vmctx *vmctx;
	int sockfd;
} thr_ctx;

static int
handle_message(struct vmctx *ctx, nvlist_t *nvl)
{
	const char *cmd;
	struct ipc_command **ipc_cmd;

	cmd = nvlist_get_string(nvl, "cmd");
	IPC_COMMAND_FOREACH(ipc_cmd, ipc_cmd_set)
	{
		if (strcmp(cmd, (*ipc_cmd)->name) == 0)
			return ((*ipc_cmd)->handler(ctx, nvl));
	}

	return (EOPNOTSUPP);
}

/*
 * Listen for commands from bhyvectl
 */
static void *
ipc_thread(void *param)
{
	int fd, ret;
	nvlist_t *nvl;
	const char *cmdname;
	struct ipc_thread_ctx *ctx;

	pthread_set_name_np(pthread_self(), "IPC thread");
	ctx = (struct ipc_thread_ctx *)param;
	while ((fd = accept(ctx->sockfd, NULL, NULL)) != -1) {
		nvl = nvlist_recv(fd, 0);
		if (nvl == NULL) {
			EPRINTLN("%s: nvlist_recv() failed: %s", __func__,
			    strerror(errno));
			close(fd);
			continue;
		}

		cmdname = nvlist_get_string(nvl, "cmd");
		if (cmdname == NULL) {
			EPRINTLN("%s: missing command name", __func__);
			nvlist_destroy(nvl);
			close(fd);
			continue;
		}
		ret = handle_message(ctx->vmctx, nvl);
		if (ret != 0) {
			EPRINTLN("%s: Error invoking command '%s':  %s",
			    __func__, cmdname, strerror(ret));
		}

		nvlist_destroy(nvl);
		close(fd);
	}

	return (NULL);
}

/*
 * Create the listening socket for IPC with bhyvectl.
 */
int
init_ipc_thread(struct vmctx *ctx)
{
	struct sockaddr_un addr;
	int socket_fd;
	pthread_t ipc_pthread;
	int err;
#ifndef WITHOUT_CAPSICUM
	/* cap_rights_t rights; */
#endif

	memset(&addr, 0, sizeof(addr));
	socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (socket_fd < 0) {
		EPRINTLN("%s: Socket creation failed: %s", __func__,
		    strerror(errno));
		err = -1;
		goto fail;
	}

	addr.sun_family = AF_UNIX;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s%s", BHYVE_RUN_DIR,
	    vm_get_name(ctx));
	addr.sun_len = SUN_LEN(&addr);
	unlink(addr.sun_path);

	if (bind(socket_fd, (struct sockaddr *)&addr, addr.sun_len) != 0) {
		EPRINTLN("Failed to bind socket \"%s\": %s\n", addr.sun_path,
		    strerror(errno));
		err = -1;
		goto fail;
	}

	if (listen(socket_fd, 10) < 0) {
		EPRINTLN("ipc socket listen: %s\n", strerror(errno));
		err = errno;
		goto fail;
	}

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_ACCEPT, CAP_READ, CAP_RECV, CAP_WRITE,
	    CAP_SEND, CAP_GETSOCKOPT);

	if (caph_rights_limit(socket_fd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	memset(&thr_ctx, 0, sizeof(thr_ctx));
	thr_ctx.vmctx = ctx;
	thr_ctx.sockfd = socket_fd;

	err = pthread_create(&ipc_pthread, NULL, ipc_thread, &thr_ctx);
	if (err != 0)
		goto fail;

	return (0);
fail:
	if (socket_fd > 0)
		close(socket_fd);
	unlink(addr.sun_path);

	return (err);
}
