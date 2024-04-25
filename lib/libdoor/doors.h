#include <sys/ioccom.h>

typedef struct {
	int x;
	int y;
} foo_t;

struct door_arg_t;
struct door_info;

#define DOORSIOC_RETURN _IOR('a', 1, foo_t)
#define DOORSIOC_CALL _IOW('a', 2, foo_t)

int door_create(void (*server_procedure)(void *cookie, char *argp,
		    size_t arg_size, door_desc_t *dp, uint_t n_desc),
    void *cookie, uint_t attributes);

int door_bind(int did);

int door_unbind(void);

int door_call(int d, door_arg_t *params);

int door_return(char *data_ptr, size_t data_size, door_desc_t *desc_ptr,
    uint_t num_desc);

int door_info(int d, struct door_info *info);

int door_revoke(int d);

void (*)(door_info_t *) door_server_create(void (*create_proc)(door_info_t *));
