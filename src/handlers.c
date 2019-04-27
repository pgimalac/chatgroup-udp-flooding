#include <stdio.h>
#include <time.h>
#include <string.h>
#include <endian.h>
#include <arpa/inet.h>

#include "types.h"
#include "network.h"
#include "tlv.h"
#include "flooding.h"

static void handle_pad1(const u_int8_t *tlv, neighbour_t *n) {
    dprintf(logfd, "Pad1 received\n");
}

static void handle_padn(const u_int8_t *tlv, neighbour_t *n) {
    dprintf(logfd, "Padn of length %d received\n", tlv[1]);
}

static void handle_hello(const u_int8_t *tlv, neighbour_t *n){
    int now = time(0), is_long = tlv[1] == 16;
    chat_id_t src_id, dest_id;
    char ipstr[INET6_ADDRSTRLEN];

    memcpy(&src_id, tlv + 2, 8);

    if (inet_ntop(AF_INET6, &n->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) == 0){
        perror("inet_ntop");
    } else {
        dprintf(logfd, "Receive %s hello from (%s, %u).\n",
               is_long ? "long" : "short" , ipstr, ntohs(n->addr->sin6_port));
    }

    if (n->status == NEIGHBOUR_SYM && src_id != n->id) {
        dprintf(logfd, "He has now id %lx.\n", src_id);
    }

    n->id = src_id;

    if (is_long) {
        memcpy(&dest_id, tlv + 2 + 8, 8);
        if (dest_id != id) {
            fprintf(stderr, "%lx is not my id.\n", dest_id);
            return;
        }
    }

    if (n->status == NEIGHBOUR_POT) {
        dprintf(logfd, "Remove from potential id: %lx.\n", src_id);
        n->last_hello_send = 0;
        hashset_add(neighbours, n);
        hashset_remove(potential_neighbours, n->addr->sin6_addr.s6_addr, n->addr->sin6_port);
        n->status = NEIGHBOUR_SYM;
    }

    n->last_hello = now;
    if (is_long) {
        n->last_long_hello = now;
    }
}

static void handle_neighbour(const u_int8_t *tlv, neighbour_t *n) {
    neighbour_t *p;
    const unsigned char *ip = (const unsigned char*)tlv + 2;
    u_int16_t port;
    char ipstr[INET6_ADDRSTRLEN];

    memcpy(&port, tlv + sizeof(struct in6_addr) + 2, sizeof(port));

    if (inet_ntop(AF_INET6, &n->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) == 0){
        perror("inet_ntop");
    } else {
        dprintf(logfd, "Receive potential neighbour from (%s, %u).\n", ipstr, ntohs(n->addr->sin6_port));
    }

    if (inet_ntop(AF_INET6, ip, ipstr, INET6_ADDRSTRLEN) == 0){
        perror("inet_ntop");
    } else {
        dprintf(logfd, "New potential neighbour (%s, %u).\n", ipstr, ntohs(port));
    }

    p = hashset_get(neighbours, ip, port);
    if (p) {
        dprintf(logfd, "Neighbour (%s, %u) already known.\n", ipstr, ntohs(port));
        return;
    }

    p = hashset_get(potential_neighbours, ip, port);
    if (p) {
        dprintf(logfd, "Neighbour (%s, %u) already known.\n", ipstr, ntohs(port));
        return;
    }

    if (!new_neighbour(ip, port, n)) {
        fprintf(stderr, "An error occured while adding peer to potential neighbours.\n");
    }
}

static void handle_data(const u_int8_t *tlv, neighbour_t *n){
    int rc;
    unsigned int size = tlv[1] - 13;
    hashmap_t *map;
    body_t *body;
    char buff[243];
    u_int8_t buffer[18];

    dprintf(logfd, "Data received.\nData type %u.\n", tlv[14]);

    map = hashmap_get(flooding_map, tlv + 2);

    if (!map) {
        dprintf(logfd, "New message received.\n");
        if (tlv[14] == 0) {
            memcpy(buff, tlv + 15, size);
            buff[size] = '\0';
            printf("%s\n", buff);
        }

        rc = flooding_add_message(tlv, tlv[1] + 2);
        if (rc < 0) {
            fprintf(stderr, "Problem while adding data to flooding map.\n");
            return;
        }

        map = hashmap_get(flooding_map, tlv + 2);
    }

    chat_id_t sender = *(chat_id_t*)(tlv + 2);
    nonce_t nonce = *(chat_id_t*)(tlv + 10);
    body = malloc(sizeof(body_t));
    body->size = tlv_ack(&body->content, sender, nonce);
    body->next = NULL;

    push_tlv(body, n);

    bytes_from_neighbour(n, buffer);
    hashmap_remove(map, buffer, 1, 1);
}

static void handle_ack(const u_int8_t *tlv, neighbour_t *n){
    char ipstr[INET6_ADDRSTRLEN];
    u_int8_t buffer[18];

    if (inet_ntop(AF_INET6, &n->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) == 0){
        perror("inet_ntop");
    } else {
        dprintf(logfd, "Ack from (%s, %u).\n", ipstr, ntohs(n->addr->sin6_port));
    }

    hashmap_t *map = hashmap_get(flooding_map, (void*)(tlv + 2));
    if (!map) {
        dprintf(logfd, "Not necessary ack\n");
        return;
    }

    bytes_from_neighbour(n, buffer);
    hashmap_remove(map, buffer, 1, 1);
}

static void handle_goaway(const u_int8_t *tlv, neighbour_t *n){
    char *msg = 0, ipstr[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &n->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) == 0){
        perror("inet_ntop");
    } else {
        dprintf(logfd, "Go away from (%s, %u).\n", ipstr, ntohs(n->addr->sin6_port));
    }

    switch(tlv[2]) {
    case GO_AWAY_UNKNOWN:
        dprintf(logfd, "Ask you to go away for an unknown reason.\n");
        break;
    case GO_AWAY_LEAVE:
        dprintf(logfd, "Leaving the network.\n");
        break;
    case GO_AWAY_HELLO:
        dprintf(logfd, "You did not send long hello or data for too long.\n");
        break;
    case GO_AWAY_BROKEN:
        dprintf(logfd, "You broke the protocol.\n");
        break;
    }

    if (tlv[1] > 0 && msg) {
        msg = malloc(tlv[1]);
        memcpy(msg, tlv + 3, tlv[1] - 1);
        msg[(int)tlv[1]] = 0;
        dprintf(logfd, "Go away message: %s\n", msg);
        free(msg);
    }

    if (hashset_remove(neighbours, n->addr->sin6_addr.s6_addr, n->addr->sin6_port)) {
        dprintf(logfd, "Remove %lx from friends.\n", n->id);
    }

    dprintf(logfd, "Add (%s, %u) to potential friends", ipstr, ntohs(n->addr->sin6_port));
    hashset_add(potential_neighbours, n);
}

static void handle_warning(const u_int8_t *tlv, neighbour_t *n){
    if (tlv[1] == 0) {
        dprintf(logfd, "Receive empty hello\n");
        return;
    }

    char *msg = malloc(tlv[1] + 1);
    memcpy(msg, tlv + 2, tlv[1]);
    msg[(int)tlv[1]] = 0;
    dprintf(logfd, "Warning: %s\n", msg);
    free(msg);
}

static void handle_unknown(const u_int8_t *tlv, neighbour_t *n){
    dprintf(logfd, "Unknown tlv type received %u\n", tlv[0]);
}

static void (*handlers[NUMBER_TLV_TYPE + 1])(const u_int8_t*, neighbour_t*) = {
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

void handle_tlv(const body_t *tlv, neighbour_t *n) {
    do {
        if (tlv->content[0] >= NUMBER_TLV_TYPE) {
            handlers[NUMBER_TLV_TYPE](tlv->content, n);
        } else if (n->status == NEIGHBOUR_SYM ||
                   (n->status == NEIGHBOUR_POT && tlv->content[0] == BODY_HELLO)) {
            handlers[(int)tlv->content[0]](tlv->content, n);
        }
    } while ((tlv = tlv->next) != NULL);
    dprintf(logfd, "\n");
}
