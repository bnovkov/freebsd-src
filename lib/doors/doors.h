#include <sys/ioccom.h>

typedef struct {
    int x;
    int y;
} foo_t;

#define DOORSIOC_RETURN	_IOR('a', 1, foo_t)
#define DOORSIOC_CALL	_IOW('a', 2, foo_t)