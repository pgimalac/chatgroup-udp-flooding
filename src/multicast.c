#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>

#include "utils.h"
#include "types.h"
#include "network.h"
#include "tlv.h"
#include "multicast.h"

time_t last_multicast = 0;
#define MULTICAST_INTERVAL 30

int init_multicast() {
    u_int8_t ip[16];
    inet_pton(AF_INET6, "ff12:b456:dad4:cee1:4589:71de:a2ec:e66", ip);

    struct sockaddr_in6 *addr = malloc(sizeof(struct sockaddr_in6));
    if (addr == NULL){
        cperror("malloc");
        return -1;
    }

    memset(addr, 0, sizeof(struct sockaddr_in6));
    addr->sin6_family = AF_INET6;
    addr->sin6_port = htons(1212);
    memcpy(addr->sin6_addr.s6_addr, ip, sizeof(struct in6_addr));

    multicast = malloc(sizeof(neighbour_t));
    if (multicast == NULL){
        cperror("malloc");
        free(addr);
        return -1;
    }

    time_t now = time(0);

    memset(multicast, 0, sizeof(neighbour_t));
    multicast->pmtu = DEF_PMTU;
    multicast->pmtu_discovery_max = DEF_PMTU << 1;
    multicast->short_hello_count = 0;
    multicast->addr = addr;
    multicast->last_neighbour_send = now;
    multicast->last_pmtu_discovery = now;
    multicast->status = NEIGHBOUR_POT;
    multicast->tutor_id = 0;

    return 0;
}

int hello_multicast(struct timeval *tv) {
    body_t *hello;
    time_t now = time(0), delta = now - last_multicast;
    if (delta >= MULTICAST_INTERVAL) {
        hello = malloc(sizeof(body_t));
        if (!hello) return -1;
        hello->size = tlv_hello_short(&hello->content, id);
        push_tlv(hello, multicast);
        last_multicast = now;
    } else if (MULTICAST_INTERVAL - delta < tv->tv_sec) {
        tv->tv_sec = MULTICAST_INTERVAL - delta;
    }

    return 0;
}
