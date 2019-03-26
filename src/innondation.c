#include <stdio.h>
#include <time.h>
#include <string.h>
#include <endian.h>
#include <arpa/inet.h>

#include "types.h"
#include "network.h"
#include "tlv.h"
#include "innondation.h"

#define MAX_TIMEOUT 30

void hello_potential_neighbours(int sock) {
    int rc;
    neighbour_t *p;

    for (p = potential_neighbours; p; p = p->next) {
        body_t hello = { 0 };
        hello.size = tlv_hello_short(&hello.content, id);

        message_t message = { 0 };
        message.magic = 93;
        message.version = 2;
        message.body_length = htons(hello.size);
        message.body = &hello;

        char ipstr[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &p->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) == 0){
            perror("inet_ntop");
        } else {
            printf("Send short hello to %s.\n", ipstr);
        }

        rc = send_message(p, sock, &message);
        if (rc < 0) perror("send message");
    }
}

int hello_neighbours(int sock, struct timeval *tv) {
    neighbour_t *p;
    int rc, size = 0;
    time_t now = time(0), delta;
    tv->tv_sec = MAX_TIMEOUT;
    tv->tv_usec = 0;

    for (p = neighbours; p; p = p->next, size++) {
        if (now - p->last_hello < 120) {
            delta = now - p->last_hello_send;
            if (delta >= 30) {
                printf("Send long hello to %lu.\n", p->id);
                body_t hello = { 0 };
                hello.size = tlv_hello_long(&hello.content, id, p->id);

                message_t message = { 0 };
                message.magic = 93;
                message.version = 2;
                message.body_length = htons(hello.size);
                message.body = &hello;

                p->last_hello_send = now;
                rc = send_message(p, sock, &message);
                if (rc < 0) perror("send message");
            } else if (MAX_TIMEOUT - delta < tv->tv_sec) {
                tv->tv_sec = MAX_TIMEOUT - delta;
            }
        }
    }

    printf("Timeout before next send loop %ld.\n", tv->tv_sec);

    return size;
}
