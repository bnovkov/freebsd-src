#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "doors.h"

int
door_create(void (*server_procedure)(void *cookie, char *argp, size_t arg_size,
		door_desc_t *dp, u_int n_desc),
    void *cookie, u_int attributes)
{
	(void)server_procedure;
	(void)cookie;
	(void)attributes;
	return -1;
}

int
door_bind(int did)
{
	(void)did;
	return -1;
}

int
door_unbind(void)
{
	return -1;
}

int
door_call(int d, door_arg_t *params)
{
	(void)d;
	(void)params;
	return -1;
}

int
door_return(char *data_ptr, size_t data_size, door_desc_t *desc_ptr,
    u_int num_desc)
{
	(void)data_ptr;
	(void)data_size;
	(void)desc_ptr;
	(void)num_desc;
	return -1;
}

int
door_info(int d, struct door_info *info)
{
	(void)d;
	(void)info;
	return -1;
}

int
door_revoke(int d)
{
	(void)d;
	return -1;
}

door_server_func *
door_server_create(void (*create_proc)(door_info_t *))
{
	(void)create_proc;
	return NULL;
}
