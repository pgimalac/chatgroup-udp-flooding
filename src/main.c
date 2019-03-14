#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>

#include "types.h"
#include "utils.h"
#include "network.h"

int
init() {
    int rc;
    rc = init_random();
    if (rc < 0) {
        perror("init:");
        return 1;
    }

    return init_network();
}

int main(void) {
    int rc;

    rc = init();
    if (rc != 0) return rc;
    printf("id: %ld\n", id);

    body_t hello = { 0 };
    hello.type = BODY_HELLO;
    hello.length = 8;
    hello.content = &id;
    hello.next = 0;

    body_t pad = { 0 };
    pad.type = BODY_PADN;
    pad.length = 2;
    pad.content = calloc(2, 1);
    pad.next = &hello;

    message_t message = { 0 };
    message.magic = 93;
    message.version = 2;
    message.body_length = 14;
    message.body = &pad;

    size_t len = 2;
    struct iovec *iov = message_to_iovec(&message, &len);

    int fd = open("out", O_WRONLY);
    writev(fd, iov, len);
    close(fd);

    fd = open("out", O_RDONLY);
    message_t m;
    read(fd, &m, 4);
    printf("%d %d %d\n", m.magic, m.version, m.body_length);

    int r = 0;
    body_t b;
    void *buf;
    while (r < m.body_length) {
        r += read(fd, &b.type, 1);
        printf("type %d ", b.type);
        if (b.type != 0) {
            r += read(fd, &b.length, 1);
            printf("length %d ", b.length);
            buf = malloc(b.length);
            r += read(fd, buf, b.length);
            if (b.type == 2)
                printf("%ld", *((chat_id_t*)buf));
        }
        printf("\n");
    }

}
