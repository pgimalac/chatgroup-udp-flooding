#include <stdio.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>

#include "types.h"
#include "network.h"
#include "tlv.h"
#include "flooding.h"
#include "interface.h"

static void handle_pad1(const u_int8_t *tlv, neighbour_t *n) {
    dprintf(logfd, "%s%sPad1 received\n%s", LOGFD_F, LOGFD_B, RESET);
}

static void handle_padn(const u_int8_t *tlv, neighbour_t *n) {
    dprintf(logfd, "%s%sPadn of length %u received\n%s", LOGFD_F, LOGFD_B, tlv[1], RESET);
}

static void handle_hello(const u_int8_t *tlv, neighbour_t *n){
    time_t now = time(0), is_long = tlv[1] == 16;
    if (now == -1){
        perrorbis(errno, "time");
        return;
    }

    chat_id_t src_id = 0, dest_id = 0;
    memcpy(&src_id, tlv + 2, sizeof(src_id));

    if (is_long)
        memcpy(&dest_id, tlv + 2 + 8, sizeof(dest_id));

    char ipstr[INET6_ADDRSTRLEN];
    assert (inet_ntop(AF_INET6, &n->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
    dprintf(logfd, "%s%sReceive %s hello from (%s, %u).\n%s", LOGFD_F, LOGFD_B,
           is_long ? "long" : "short" , ipstr, ntohs(n->addr->sin6_port), RESET);

    n->id = src_id;

    if (is_long && dest_id != id) {
        dprintf(logfd, "%s%s%lx is not my id.\n%s", LOGFD_F, LOGFD_B, dest_id, RESET);
        return;
    }

    if (n->status == NEIGHBOUR_SYM && src_id != n->id) {
        dprintf(logfd, "%s%sHe has now id %lx.\n%s", LOGFD_B, LOGFD_F, src_id, RESET);
    }

    if (n->status == NEIGHBOUR_POT) {
        dprintf(logfd, "%s%sRemove from potential %lx and add to symetrical.\n%s", LOGFD_F, LOGFD_B, src_id, RESET);
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

    assert (inet_ntop(AF_INET6, &n->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
    dprintf(logfd, "%s%sReceive potential neighbour from (%s, %u).\n%s", LOGFD_F, LOGFD_B, ipstr, ntohs(n->addr->sin6_port), RESET);

    assert (inet_ntop(AF_INET6, ip, ipstr, INET6_ADDRSTRLEN) != NULL);
    dprintf(logfd, "%s%sNew potential neighbour (%s, %u).\n%s", LOGFD_F, LOGFD_B, ipstr, ntohs(port), RESET);

    p = hashset_get(neighbours, ip, port);
    if (p) {
        dprintf(logfd, "%s%sNeighbour (%s, %u) already known.\n%s", LOGFD_F, LOGFD_B, ipstr, ntohs(port), RESET);
        return;
    }

    p = hashset_get(potential_neighbours, ip, port);
    if (p) {
        dprintf(logfd, "%s%sNeighbour (%s, %u) already known.\n%s", LOGFD_F, LOGFD_B, ipstr, ntohs(port), RESET);
        return;
    }

    if (max(neighbours->size, potential_neighbours->size) >= MAX_NB_NEIGHBOUR){
        dprintf(logfd, "%s%sAlready too much neighbours so (%s, %u) wasn't added in the potentials.\n%s", LOGFD_F, LOGFD_B, ipstr, ntohs(port), RESET);
        return;
    }

    if (!new_neighbour(ip, port, n))
        fprintf(stderr, "%s%sAn error occured while adding peer to potential neighbours.\n%s", STDERR_F, STDERR_B, RESET);
}

static void handle_data(const u_int8_t *tlv, neighbour_t *n){
    int rc;
    unsigned int size = tlv[1] - 13;
    hashmap_t *map;
    body_t *body;
    char buff[243];
    u_int8_t buffer[18];

    dprintf(logfd, "%s%sData received.\nData type %u.\n%s", LOGFD_F, LOGFD_B, tlv[14], RESET);

    map = hashmap_get(flooding_map, tlv + 2);


    if (!map && !hashmap_get(data_map, tlv + 2)) {
        dprintf(logfd, "%s%sNew message received.\n%s", LOGFD_F, LOGFD_B, RESET);

        if (tlv[14] == 0) {
            memcpy(buff, tlv + 15, size);
            buff[size] = '\0';
            printf("%s%s%s\n%s", STDOUT_B, STDOUT_F, buff, RESET);
        }

        rc = flooding_add_message(tlv, tlv[1] + 2);
        if (rc < 0) {
            fprintf(stderr, "%s%sProblem while adding data to flooding map.\n%s", LOGFD_F, LOGFD_B, RESET);
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
    datime_t *datime;

    assert (inet_ntop(AF_INET6, &n->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
    dprintf(logfd, "%s%sAck from (%s, %u).\n%s", LOGFD_F, LOGFD_B, ipstr, ntohs(n->addr->sin6_port), RESET);

    hashmap_t *map = hashmap_get(flooding_map, (void*)(tlv + 2));
    if (!map) {
        dprintf(logfd, "%s%sNot necessary ack\n%s", LOGFD_F, LOGFD_B, RESET);
        return;
    }

    datime = hashmap_get(data_map, tlv + 2);
    datime->last = time(0);

    bytes_from_neighbour(n, buffer);
    hashmap_remove(map, buffer, 1, 1);
}

static void handle_goaway(const u_int8_t *tlv, neighbour_t *n){
    char *msg = 0, ipstr[INET6_ADDRSTRLEN];
    assert (inet_ntop(AF_INET6, &n->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
    dprintf(logfd, "%s%sGo away from (%s, %u).\n%s", LOGFD_F, LOGFD_B, ipstr, ntohs(n->addr->sin6_port), RESET);

    switch(tlv[2]) {
    case GO_AWAY_UNKNOWN:
        dprintf(logfd, "%s%sAsk you to go away for an unknown reason.\n%s", LOGFD_F, LOGFD_B, RESET);
        break;
    case GO_AWAY_LEAVE:
        dprintf(logfd, "%s%sLeaving the network.\n%s", LOGFD_F, LOGFD_B, RESET);
        break;
    case GO_AWAY_HELLO:
        dprintf(logfd, "%s%sYou did not send long hello or data for too long.\n%s", LOGFD_F, LOGFD_B, RESET);
        break;
    case GO_AWAY_BROKEN:
        dprintf(logfd, "%s%sYou broke the protocol.\n%s", LOGFD_F, LOGFD_B, RESET);
        break;
    }

    if (tlv[1] > 0 && msg) {
        msg = malloc(tlv[1]);
        memcpy(msg, tlv + 3, tlv[1] - 1);
        msg[(int)tlv[1]] = 0;
        dprintf(logfd, "%s%sGo away message: %s\n%s", LOGFD_F, LOGFD_B, msg, RESET);
        free(msg);
    }

    if (hashset_remove(neighbours, n->addr->sin6_addr.s6_addr, n->addr->sin6_port)) {
        dprintf(logfd, "%s%sRemove %lx from friends.\n%s", LOGFD_F, LOGFD_B, n->id, RESET);
    }

    dprintf(logfd, "%s%sAdd (%s, %u) to potential friends\n%s", LOGFD_F, LOGFD_B, ipstr, ntohs(n->addr->sin6_port), RESET);
    hashset_add(potential_neighbours, n);
}

static void handle_warning(const u_int8_t *tlv, neighbour_t *n){
    if (tlv[1] == 0) {
        dprintf(logfd, "%s%sReceive empty hello\n%s", LOGFD_F, LOGFD_B, RESET);
        return;
    }

    char *msg = malloc(tlv[1] + 1);
    memcpy(msg, tlv + 2, tlv[1]);
    msg[(int)tlv[1]] = 0;
    dprintf(logfd, "%s%sWarning: %s\n%s", LOGFD_F, LOGFD_B, msg, RESET);
    free(msg);
}

static void handle_unknown(const u_int8_t *tlv, neighbour_t *n){
    dprintf(logfd, "%s%sUnknown tlv type received %u\n%s", LOGFD_F, LOGFD_B, tlv[0], RESET);
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
    dprintf(logfd, "%s%s\n%s", LOGFD_B, LOGFD_F, RESET);
}
