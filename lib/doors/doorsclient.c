#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "doors.h"

int main()
{

    foo_t test = { 1, 2 };

    int dev = open("/dev/door", O_RDONLY);
    if (dev == -1) {
        printf("Can't open device");
        return -1;
    }

    ioctl(dev, DOORSIOC_RETURN, &test);
    ioctl(dev, DOORSIOC_CALL, &test);

    close(dev);

    return 0;
}
