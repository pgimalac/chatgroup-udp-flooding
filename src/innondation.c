#include <stdio.h>
#include <time.h>
#include <string.h>
#include <endian.h>
#include <arpa/inet.h>

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

        char ipstr[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &p->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) == 0){
            perror("inet_ntop");
        } else {
            printf("Send short hello to %s.\n", ipstr);
        }
    }
}

int hello_neighbours(int sock, struct timeval *tv) {
    neighbour_t *p;
    int rc, gap, size = 0;
    time_t now = time(0);
    tv->tv_sec = 10;
    tv->tv_usec = 0;

    for (p = neighbours; p; p = p->next, size++) {
        if (now - p->last_hello < 120 || now - p->last_long_hello < 120) {
            gap = (now - p->last_hello) % 30; // todo change
            if (gap < tv->tv_sec) tv->tv_sec = gap;

            if (now - p->last_hello_send > 30) {
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
            }
        }
    }

    return size;
}

int is_neighbour(neighbour_t *n, const struct sockaddr_in6 *addr) {
    struct sockaddr_in6 *sin = n->addr;
    return
        memcmp(&sin->sin6_addr, &addr->sin6_addr, sizeof(struct in6_addr)) == 0 &&
        sin->sin6_port == addr->sin6_port;
}

neighbour_t *
remove_from_potential_neigbours(chat_id_t source_id, const struct sockaddr_in6 *addr) {
    neighbour_t *ret = 0, *p;

    if (potential_neighbours) {
        if (is_neighbour(potential_neighbours, addr)) {
            ret = potential_neighbours;
            potential_neighbours = ret->next;
        } else {
            for (p = potential_neighbours; p->next; p = p->next)
                if (is_neighbour(p->next, addr)) {
                    ret = p->next;
                    p->next = ret->next;
                }
        }
    }

    if (ret) {
        printf("Remove from potential id: %lu.\n", source_id);
        ret->id = source_id;
        ret->next = neighbours;
        neighbours = ret;
    }

    return ret;
}

int update_hello(const chat_id_t *ids, size_t len, const struct sockaddr_in6 *addr) {
    neighbour_t *n = 0;
    int now = time(0);
    chat_id_t source_id = ids[0];
    char ipstr[INET6_ADDRSTRLEN];

    if (inet_ntop(AF_INET6, &addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) == 0){
        perror("inet_ntop");
    } else {
        printf("Receive hello %s from (%s, %u).\n",
               len == 2 ? "long" : "short" , ipstr, addr->sin6_port);
    }

    if (len == 2 && ids[1] != id) {
        fprintf(stderr, "%lu is not my id.\n", ids[1]);
        return -1;
    }

    n = remove_from_potential_neigbours(source_id, addr);

    if (!n) {
        for (n = neighbours; n; n = n->next) {
            if (n->id == source_id) break;
        }
    }

    if (!n) {
        printf("New friend %lu.\n", source_id);
        struct sockaddr_in6 *copy = malloc(sizeof(struct sockaddr_in6));
        if (!copy) return -3;
        memcpy(copy, addr, sizeof(struct sockaddr_in6));

        n = malloc(sizeof(neighbour_t));
        if (!n) {
            free(copy);
            return -2;
        }

        n->last_hello_send = 0;
        n->id = source_id;
        n->addr = copy;
        n->next = neighbours;
        neighbours = n;
    }

    n->last_hello = now;
    if (len > 2) {
        n->last_long_hello = now;
    }
    return 0;
}

int update_neighbours(const struct in6_addr *ip, u_int16_t port) {
    neighbour_t *p;

    for (p = neighbours; p; p = p->next)
        if (memcmp(ip, &p->addr->sin6_addr, sizeof(struct in6_addr)) == 0 &&
            p->addr->sin6_port == port) return 1;

    for (p = potential_neighbours; p; p = p->next)
        if (memcmp(ip, &p->addr->sin6_addr, sizeof(struct in6_addr)) == 0 &&
            p->addr->sin6_port == port) return 1;

    struct sockaddr_in6 *addr = malloc(sizeof(struct sockaddr_in6));
    if (!addr) return -3;
    memset(addr, 0, sizeof(struct sockaddr_in6));
    memmove(&addr->sin6_addr, ip, sizeof(struct in6_addr));
    addr->sin6_port = port;

    p = malloc(sizeof(neighbour_t));
    if (!p) {
        free(addr);
        return -2;
    }

    p->id = 0;
    p->addr = addr;
    p->next = potential_neighbours;
    potential_neighbours = p;
    return 0;
}
