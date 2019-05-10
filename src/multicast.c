#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>
#include <ifaddrs.h>

#include "utils.h"
#include "types.h"
#include "network.h"
#include "tlv.h"
#include "multicast.h"

struct ifaddrs *ifap = 0;
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
    memcpy(&addr->sin6_addr, ip, sizeof(struct in6_addr));

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

int join_group_on_all_interfaces(int s) {
    struct ipv6_mreq mreq = { 0 };
    struct ifaddrs *p;
    int ifindex, rc;
    char out[INET6_ADDRSTRLEN];

    rc = getifaddrs(&ifap);
    if (rc < 0) {
        cperror("getifaddrs");
        return -1;
    }

    for (p = ifap; p; p = p->ifa_next) {
        ifindex = if_nametoindex(p->ifa_name);
        if (ifindex < 0) {
            cperror("if_nametoindex");
            return -3;
        }

        memcpy(&mreq.ipv6mr_multiaddr, &multicast->addr->sin6_addr, 16);
        mreq.ipv6mr_interface = ifindex;

        rc = setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq));
        if (rc < 0) {
            cperror("setsockopt");
            return -3;
        }

        inet_ntop(AF_INET6, &mreq.ipv6mr_multiaddr, out, INET6_ADDRSTRLEN);
        cprint(STDOUT_FILENO, "Join multicast group %s on interface %s.\n",
               out, p->ifa_name);
    }

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
