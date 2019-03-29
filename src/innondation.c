#include <stdio.h>
#include <time.h>
#include <string.h>
#include <endian.h>
#include <arpa/inet.h>

#include "types.h"
#include "network.h"
#include "tlv.h"
#include "innondation.h"
#include "utils.h"
#include "structs/list.h"

#define MAX_TIMEOUT 30

void hello_potential_neighbours() {
    int rc, i;
    list_t *l;
    neighbour_t *p;
    body_t hello = { 0 };
    hello.size = tlv_hello_short(&hello.content, id);

    message_t message = { 0 };
    message.magic = 93;
    message.version = 2;
    message.body_length = htons(hello.size);
    message.body = &hello;

    for (i = 0; i < potential_neighbours->capacity; i++) {
        for (l = potential_neighbours->tab[i]; l; l = l->next) {
            p = (neighbour_t*)l->val;
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

    free_message(&message, 0);
}

int hello_neighbours(struct timeval *tv) {
    neighbour_t *p;
    int i, rc, size = 0;
    time_t now = time(0), delta;
    list_t *l;
    tv->tv_sec = MAX_TIMEOUT;
    tv->tv_usec = 0;

    for (i = 0; i < neighbours->capacity; i++) {
        for (l = neighbours->tab[i]; l; l = l->next, size++) {
            p = (neighbour_t*)l->val;
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
                    free_message(&message, 0);
                    if (rc < 0) perror("send message");
                } else if (MAX_TIMEOUT - delta < tv->tv_sec) {
                    tv->tv_sec = MAX_TIMEOUT - delta;
                }
            }
        }
    }

    printf("Timeout before next send loop %ld.\n", tv->tv_sec);

    return size;
}
