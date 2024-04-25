#include <sys/ioccom.h>

typedef struct {
	int x;
	int y;
} foo_t;

typedef struct door_arg_t door_arg_t;
typedef struct door_info door_info_t;
typedef struct door_desc_t door_desc_t;
typedef void door_server_func(door_info_t *);

#define DOORSIOC_RETURN _IOR('a', 1, foo_t)
#define DOORSIOC_CALL _IOW('a', 2, foo_t)

int door_create(void (*server_procedure)(void *cookie, char *argp,
		    size_t arg_size, door_desc_t *dp, u_int n_desc),
    void *cookie, u_int attributes);

int door_bind(int did);

int door_unbind(void);

int door_call(int d, door_arg_t *params);

int door_return(char *data_ptr, size_t data_size, door_desc_t *desc_ptr,
    u_int num_desc);

int door_info(int d, struct door_info *info);

int door_revoke(int d);

door_server_func *door_server_create(void (*create_proc)(door_info_t *));
