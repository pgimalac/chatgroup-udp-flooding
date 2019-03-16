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
    printf("id: %lu\n", id);

    s = start_server(PORT);
    if (s < 0) {
        fprintf(stderr, "coudn't create socket\n");
        return 1;
    }

    rc = add_neighbour("jch.irif.fr", "1212", &neighbours);
    if (rc < 0) {
        perror("add neighbour");
        return 2;
    }

    chat_id_t i = htonl(id);
    body_t hello = { 0 };
    hello.type = BODY_HELLO;
    hello.length = 8;
    hello.content = &i;
    hello.next = 0;

    body_t pad = { 0 };
    pad.type = BODY_PADN;
    pad.length = 2;
    char buf[2] = {0}; // better than calloc(2)
    pad.content = buf;
    pad.next = &hello;

    message_t message = { 0 };
    message.magic = 93;
    message.version = 2;
    message.body_length = htons(14);
    message.body = &pad;

    rc = send_message(neighbours, s, &message, 2);
    if (rc < 0) {
        perror("send message");
        return 1;
    }

    while (1) {
        char c[4096];
        size_t len = 4096;
        struct in6_addr addr = { 0 };
        rc = recv_message(s, &addr, c, &len);
        if (rc < 0) {
            perror("receive message");
            return 1;
        }

        message_t *msg = bytes_to_message(c, len);
        printf("Message description:\n");
        printf("magic: %d\n", msg->magic);
        printf("version: %d\n", msg->version);
        printf("body length: %d\n\n", msg->body_length);

        for(body_t *p = msg->body; p; p = p->next) {
            printf("Next TLV\n");
            printf("type: %d\n", p->type);
            printf("length: %d\n\n", p->length);
        }

        free_message(msg);
    }

    printf("Bye !\n");

    return 0;
}
