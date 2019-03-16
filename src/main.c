#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>

#include "types.h"
#include "utils.h"
#include "network.h"

#define PORT 4242

int init() {
    int rc;
    rc = init_random();
    if (rc < 0) {
        perror("init");
        return 1;
    }

    return init_network();
}

int main(void) {
    int rc, s;

    rc = init();
    if (rc != 0) return rc;
    printf("id: %ld\n", id);

    s = start_server(PORT);
    if (s < 0) {
        fprintf(stderr, "coudn't create socket\n");
        return 1;
    }

    rc = add_neighbour("jch.irif.fr", "1212", &neighbours);
    if (rc < 0) {
        return 2;
    }

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

    rc = send_message(neighbours, s, &message, 2);
    if (rc < 0) {
        perror("send message");
        printf("%d\n", rc);
    }
}
