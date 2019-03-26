#include <stdio.h>
#include <time.h>
#include <string.h>
#include <endian.h>
#include <arpa/inet.h>

#include "types.h"
#include "network.h"
#include "tlv.h"

#define NUMBER_TLV_TYPE 8

static void handle_pad1(const char *tlv, const struct sockaddr_in6 *addr) {
    printf("Pad1 received\n");
}

static void handle_padn(const char *tlv, const struct sockaddr_in6 *addr) {
    printf("Pad %d received\n", tlv[0]);
}

static int is_neighbour(neighbour_t *n, const struct sockaddr_in6 *addr) {
    struct sockaddr_in6 *sin = n->addr;
    return
        memcmp(&sin->sin6_addr, &addr->sin6_addr, sizeof(struct in6_addr)) == 0 &&
        sin->sin6_port == addr->sin6_port;
}


static neighbour_t *
remove_from_potential_neigbours(chat_id_t source_id, const struct sockaddr_in6 *addr) {
    neighbour_t *ret = 0, *p;

    if (potential_neighbours) {
        if (is_neighbour(potential_neighbours, addr)) {
            ret = potential_neighbours;
            potential_neighbours = ret->next;
        } else {
            int size = 1;
            for (p = potential_neighbours; p->next; p = p->next, size++)
                if (is_neighbour(p->next, addr)) {
                    ret = p->next;
                    p->next = ret->next;
                }
            printf("potential friends length %d\n", size);
        }
    }

    if (ret) {
        printf("Remove from potential id: %lu.\n", source_id);
        ret->last_hello_send = 0;
        ret->id = source_id;
        ret->next = neighbours;
        neighbours = ret;
    }

    return ret;
}


static void handle_hello(const char *tlv, const struct sockaddr_in6 *addr){
    neighbour_t *n = 0;
    int now = time(0), is_long = tlv[1] == 16;
    chat_id_t src_id, dest_id;
    char ipstr[INET6_ADDRSTRLEN];

    memcpy(&src_id, tlv + 2, 8);

    if (inet_ntop(AF_INET6, &addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) == 0){
        perror("inet_ntop");
    } else {
        printf("Receive hello %s from (%s, %u).\n",
               is_long ? "long" : "short" , ipstr, htons(addr->sin6_port));
    }

    if (is_long) {
        memcpy(&dest_id, tlv + 2 + 8, 8);
        if (dest_id != id) {
            fprintf(stderr, "%lu is not my id.\n", dest_id);
            return;
        }
    }

    n = remove_from_potential_neigbours(src_id, addr);

    if (!n) {
        for (n = neighbours; n; n = n->next) {
            if (n->id == src_id) break;
        }
    }

    if (!n) {
        printf("New friend %lu.\n", src_id);
        struct sockaddr_in6 *copy = malloc(sizeof(struct sockaddr_in6));
        if (!copy) return;
        memcpy(copy, addr, sizeof(struct sockaddr_in6));

        n = malloc(sizeof(neighbour_t));
        if (!n) {
            free(copy);
            return;
        }

        n->last_hello_send = 0;
        n->id = src_id;
        n->addr = copy;
        n->next = neighbours;
        neighbours = n;
    }

    n->last_hello = now;
    if (is_long) {
        n->last_long_hello = now;
    }
}

static void handle_neighbour(const char *tlv, const struct sockaddr_in6 *addr) {
    neighbour_t *p;
    struct in6_addr *ip = (struct in6_addr*)(tlv + 2);
    u_int16_t port;
    char ipstr[INET6_ADDRSTRLEN];

    memcpy(&port, tlv + sizeof(struct in6_addr) + 2, 2);

    for (p = neighbours; p; p = p->next)
        if (memcmp(ip, &p->addr->sin6_addr, sizeof(struct in6_addr)) == 0 &&
            p->addr->sin6_port == port) return;

    for (p = potential_neighbours; p; p = p->next)
        if (memcmp(ip, &p->addr->sin6_addr, sizeof(struct in6_addr)) == 0 &&
            p->addr->sin6_port == port) return;

    struct sockaddr_in6 *n_addr = malloc(sizeof(struct sockaddr_in6));
    if (!n_addr) return;
    memset(n_addr, 0, sizeof(struct sockaddr_in6));
    memmove(&n_addr->sin6_addr, ip, sizeof(struct in6_addr));
    n_addr->sin6_port = port;
    n_addr->sin6_family = AF_INET6;

    p = malloc(sizeof(neighbour_t));
    if (!p) {
        free(n_addr);
        return;
    }

    p->id = 0;
    p->addr = n_addr;
    p->next = potential_neighbours;
    potential_neighbours = p;

    if (inet_ntop(AF_INET6, &n_addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) == 0){
        perror("inet_ntop");
    } else {
        printf("New potential neighbour (%s, %u).\n", ipstr, htons(addr->sin6_port));
    }
}

static void handle_data(const char *tlv, const struct sockaddr_in6 *addr){
    printf("DATA\n");
}

static void handle_ack(const char *tlv, const struct sockaddr_in6 *addr){
    printf("ACK\n");
}

static void handle_goaway(const char *tlv, const struct sockaddr_in6 *addr){
    char *msg = 0, ipstr[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) == 0){
        perror("inet_ntop");
    } else {
        printf("Go away from (%s, %u).\n", ipstr, htons(addr->sin6_port));
    }

    switch(tlv[2]) {
    case GO_AWAY_UNKNOWN:
        printf("Ask you to go away for an unknown reason.\n");
        break;
    case GO_AWAY_LEAVE:
        printf("Leaving the network.\n");
        break;
    case GO_AWAY_HELLO:
        printf("You did not send long hello for too long.\n");
        break;
    case GO_AWAY_BROKEN:
        printf("You broke the protocol.\n");
        break;
    }

    if (tlv[1] > 0 && msg) {
        msg = malloc(tlv[1]);
        memcpy(msg, tlv + 3, tlv[1] - 1);
        msg[(int)tlv[1]] = 0;
        printf("Go away message: %s\n", msg);
        free(msg);
    }
}

static void handle_warning(const char *tlv, const struct sockaddr_in6 *addr){
    if (tlv[1] == 0) {
        printf("Received empty hello\n");
        return;
    }

    char *msg = malloc(tlv[1] + 1);
    memcpy(msg, tlv + 2, tlv[1]);
    msg[(int)tlv[1]] = 0;
    printf("Warning: %s\n", msg);
    free(msg);
}

static void handle_unknown(const char *tlv, const struct sockaddr_in6 *addr){
    printf("UNKNOWN\n");
}

static void (*handlers[NUMBER_TLV_TYPE + 1])(const char*, const struct sockaddr_in6*) = {
    handle_pad1,
    handle_padn,
    handle_hello,
    handle_neighbour,
    handle_data,
    handle_ack,
    handle_goaway,
    handle_warning,
    handle_unknown
};

void handle_tlv(const body_t *tlv, const struct sockaddr_in6 *addr) {
    do {
        if (tlv->content[0] != BODY_PAD1 &&
            (tlv->content[0] >= NUMBER_TLV_TYPE || tlv->content[0] < 0)) {
            handlers[NUMBER_TLV_TYPE](tlv->content, addr);
        } else {
            handlers[(int)tlv->content[0]](tlv->content, addr);
        }
    } while ((tlv = tlv->next) != NULL);
    printf("\n\n");
}
