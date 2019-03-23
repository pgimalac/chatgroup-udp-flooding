#include <stdio.h>
#include <time.h>
#include <string.h>

#include "types.h"
#include "network.h"
#include "tlv.h"

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

        rc = send_message(p, sock, &message);
        if (rc < 0) perror("send message");
    }
}

int hello_neighbours(int sock, struct timeval *tv) {
    neighbour_t *p;
    int rc, gap, size = 0;
    time_t now = time(0);
    tv->tv_sec = 30;
    tv->tv_usec = 0;

    for (p = neighbours; p; p = p->next, size++) {
        if (now - p->last_hello < 120 || now - p->last_long_hello < 120) {
            gap = (now - p->last_hello) % 30; // todo change
            if (gap < tv->tv_sec) tv->tv_sec = gap;

            body_t hello = { 0 };
            hello.size = tlv_hello_long(&hello.content, id, p->id);

            message_t message = { 0 };
            message.magic = 93;
            message.version = 2;
            message.body_length = htons(hello.size);
            message.body = &hello;

            rc = send_message(p, sock, &message);
            if (rc < 0) perror("send message");
        }
    }

    return size;
}

int update_hello_short(const chat_id_t id,
                       const struct sockaddr_in6 *addr, size_t addrlen) {
    neighbour_t **l = &potential_neighbours;
    int now = time(0);

    if (*l) { // TODO: prettify
        if ((*l)->id == id) {
            (*l)->last_hello = now;
            return 1;
        }
        while (*l) {
            if ((*l)->id == id) {
                (*l)->last_hello = now;
                return 1;
            }
            l = &(*l)->next;
        }
    }

    struct sockaddr *copy = malloc(addrlen);
    if (!copy) return -3;
    memcpy(copy, addr, addrlen);

    neighbour_t *n = malloc(sizeof(neighbour_t));
    if (!n) {
        free(copy);
        return -2;
    }

    n->id = 0;
    n->last_hello = now;
    n->last_long_hello = 0;
    n->addr = copy;
    n->addrlen = addrlen;
    n->next = 0;
    (*l)->next = n;
    return 0;
}

int update_hello_long(const chat_id_t id,
                       const struct sockaddr_in6 *addr, size_t addrlen) {
    neighbour_t **l = &neighbours;
    int now = time(0);

    if (*l) { // TODO: prettify
        if ((*l)->id == id) {
            (*l)->last_hello = now;
            (*l)->last_long_hello = now;
            return 1;
        }
        while (*l) {
            if ((*l)->id == id) {
                (*l)->last_hello = now;
                (*l)->last_long_hello = now;
                return 1;
            }
            l = &(*l)->next;
        }
    }

    struct sockaddr *copy = malloc(addrlen);
    if (!copy) return -3;
    memcpy(copy, addr, addrlen);

    neighbour_t *n = malloc(sizeof(neighbour_t));
    if (!n) {
        free(copy);
        return -2;
    }

    n->id = 0;
    n->last_hello = now;
    n->last_long_hello = now;
    n->addr = copy;
    n->addrlen = addrlen;
    n->next = 0;
    (*l)->next = n;
    return 0;
}

int update_hello (const chat_id_t *hello, size_t len,
                  struct sockaddr_in6 *addr, size_t addrlen) {
    if (len == 1) return update_hello_short(hello[0], addr, addrlen);
    else if (len == 2 && hello[1] == id)
        return update_hello_long(hello[0], addr, addrlen);
    return -1;
}