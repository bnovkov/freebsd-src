#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/ioccom.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/uio.h>

#include "doors.h"

static d_ioctl_t doors_ioctl;

static struct cdevsw doors_cdevsw = {
	.d_name = "doors",
	.d_version = D_VERSION,
	.d_flags = D_TRACKCLOSE,
	.d_ioctl = doors_ioctl,
};

static struct cdev *doors_cdev;

MALLOC_DECLARE(M_DOORS);
MALLOC_DEFINE(M_DOORS, "doors", "Doors module");

static int
doors_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int flags,
    struct thread *td)
{
	int error = 0;

	switch (cmd) {
	case DOORSIOC_RETURN:
		printf("We are in return\n");
		break;
	case DOORSIOC_CALL:
		printf("We are in call\n");
		break;
	default:
		error = ENOTTY;
		break;
	}

	return (error);
}

static int
doors_modevent(module_t mod, int type, void *arg)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		doors_cdev = make_dev(&doors_cdevsw, 0, UID_ROOT, GID_WHEEL,
		    0666, "door");
		break;
	case MOD_UNLOAD: /* FALLTHROUGH */
	case MOD_SHUTDOWN:
		destroy_dev(doors_cdev);
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

DEV_MODULE(doors, doors_modevent, NULL);
