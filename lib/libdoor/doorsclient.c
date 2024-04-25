#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "doors.h"

int
door_create(void (*server_procedure)(void *cookie, char *argp, size_t arg_size,
		door_desc_t *dp, uint_t n_desc),
    void *cookie, uint_t attributes)
{
	return -1;
}

int
door_bind(int did)
{
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
	return -1;
}

int
door_return(char *data_ptr, size_t data_size, door_desc_t *desc_ptr,
    uint_t num_desc)
{
	return -1;
}

int
door_info(int d, struct door_info *info)
{
	return -1;
}

int
door_revoke(int d)
{
	return -1;
}

void (*)(door_info_t *) door_server_create(void (*create_proc)(door_info_t *))
{
	return NULL;
}
