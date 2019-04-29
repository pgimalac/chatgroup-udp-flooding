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
    cprint(0, "Pad1 received\n");
}

static void handle_padn(const u_int8_t *tlv, neighbour_t *n) {
    cprint(0, "Padn of length %u received\n", tlv[1]);
}

static void handle_hello(const u_int8_t *tlv, neighbour_t *n){
    time_t now = time(0), is_long = tlv[1] == 16;
    if (now == -1){
        cperror("time");
        return;
    }

    chat_id_t src_id = 0, dest_id = 0;
    memcpy(&src_id, tlv + 2, sizeof(src_id));

    if (is_long)
        memcpy(&dest_id, tlv + 2 + 8, sizeof(dest_id));

    char ipstr[INET6_ADDRSTRLEN];
    assert (inet_ntop(AF_INET6, &n->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
    cprint(0, "Receive %s hello from (%s, %u).\n",
           is_long ? "long" : "short" , ipstr, ntohs(n->addr->sin6_port));

    n->id = src_id;

    if (is_long && dest_id != id) {
        cprint(0, "%lx is not my id.\n", dest_id);
        return;
    }

    if (n->status == NEIGHBOUR_SYM && src_id != n->id) {
        cprint(0, "He has now id %lx.\n", src_id);
    }

    if (n->status == NEIGHBOUR_POT) {
        cprint(0, "Remove from potential %lx and add to symetrical.\n", src_id);
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
    cprint(0, "Receive potential neighbour from (%s, %u).\n", ipstr, ntohs(n->addr->sin6_port));

    assert (inet_ntop(AF_INET6, ip, ipstr, INET6_ADDRSTRLEN) != NULL);
    cprint(0, "New potential neighbour (%s, %u).\n", ipstr, ntohs(port));

    p = hashset_get(neighbours, ip, port);
    if (p) {
        cprint(0, "Neighbour (%s, %u) already known.\n", ipstr, ntohs(port));
        return;
    }

    p = hashset_get(potential_neighbours, ip, port);
    if (p) {
        cprint(0, "Neighbour (%s, %u) already known.\n", ipstr, ntohs(port));
        return;
    }

    if (max(neighbours->size, potential_neighbours->size) >= MAX_NB_NEIGHBOUR){
        cprint(0, "Already too much neighbours so (%s, %u) wasn't added in the potentials.\n", ipstr, ntohs(port));
        return;
    }

    if (!new_neighbour(ip, port, n))
        cprint(STDERR_FILENO, "An error occured while adding peer to potential neighbours.\n");
}

static void handle_data(const u_int8_t *tlv, neighbour_t *n){
    int rc;
    unsigned int size = tlv[1] - 13;
    hashmap_t *map;
    body_t *body;
    u_int8_t buffer[18];

    cprint(0, "Data received of type %u.\n", tlv[14]);

    map = hashmap_get(flooding_map, tlv + 2);


    if (!map && !hashmap_get(data_map, tlv + 2)) {
        if (tlv[14] == 0) {
            cprint(0, "New message received.\n");
            cprint(STDOUT_FILENO, "%*s\n", size, tlv + 15);
        } else if (tlv[14] == DATA_FRAG) {
            if (size < 9)
                cprint(0, "Data fragment was corrupted (too short).\n");

            char fragid[12] = { 0 };
            memcpy(fragid, tlv + 2, 8);
            memcpy(fragid + 8, tlv + 15, 4);
            frag_t *frag = hashmap_get(fragmentation_map, fragid);
            if (!frag) {
                frag = malloc(sizeof(frag_t));
                frag->id = voidndup(fragid, 12);

                memcpy(&frag->type, tlv + 19, 1);
                memcpy(&frag->size, tlv + 20, 2);
                frag->size = ntohs(frag->size);

                cprint(0, "New fragment of total size %u\n", frag->size);
                frag->recv = 0;

                frag->buffer = malloc(frag->size);
                hashmap_add(fragmentation_map, fragid, frag);
            }

            uint16_t fragpos, fragsize;
            memcpy(&fragpos, tlv + 22, 2);
            fragpos = ntohs(fragpos);
            fragsize = tlv[1] - 22;

            frag->recv += fragsize;
            frag->last = time(0);
            memcpy(frag->buffer + fragpos, tlv + 24, fragsize);

            if (frag->recv == frag->size) {
                cprint(0, "New long message received.\n");
                // TODO: check data type
                cprint(STDOUT_FILENO, "%*s\n", frag->size, frag->buffer);
                free(frag->buffer);
                free(frag->id);
                hashmap_remove(fragmentation_map, fragid, 1, 1);
            }
        }

        rc = flooding_add_message(tlv, tlv[1] + 2);
        if (rc < 0) {
            cprint(STDERR_FILENO, "Problem while adding data to flooding map.\n");
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
    cprint(0, "Ack from (%s, %u).\n", ipstr, ntohs(n->addr->sin6_port));

    hashmap_t *map = hashmap_get(flooding_map, (void*)(tlv + 2));
    if (!map) {
        cprint(0, "Not necessary ack\n");
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
    cprint(0, "Go away from (%s, %u).\n", ipstr, ntohs(n->addr->sin6_port));

    switch(tlv[2]) {
    case GO_AWAY_UNKNOWN:
        cprint(0, "Ask you to go away for an unknown reason.\n");
        break;
    case GO_AWAY_LEAVE:
        cprint(0, "Leaving the network.\n");
        break;
    case GO_AWAY_HELLO:
        cprint(0, "You did not send long hello or data for too long.\n");
        break;
    case GO_AWAY_BROKEN:
        cprint(0, "You broke the protocol.\n");
        break;
    }

    if (tlv[1] > 0 && msg) {
        msg = malloc(tlv[1]);
        memcpy(msg, tlv + 3, tlv[1] - 1);
        msg[(int)tlv[1]] = 0;
        cprint(0, "Go away message: %s\n", msg);
        free(msg);
    }

    if (hashset_remove(neighbours, n->addr->sin6_addr.s6_addr, n->addr->sin6_port)) {
        cprint(0, "Remove %lx from friends.\n", n->id);
    }

    cprint(0, "Add (%s, %u) to potential friends\n", ipstr, ntohs(n->addr->sin6_port));
    hashset_add(potential_neighbours, n);
}

static void handle_warning(const u_int8_t *tlv, neighbour_t *n){
    if (tlv[1] == 0) {
        cprint(0, "Receive empty hello\n");
        return;
    }

    char *msg = malloc(tlv[1] + 1);
    memcpy(msg, tlv + 2, tlv[1]);
    msg[(int)tlv[1]] = 0;
    cprint(0, "Warning: %s\n", msg);
    free(msg);
}

static void handle_unknown(const u_int8_t *tlv, neighbour_t *n){
    cprint(0, "Unknown tlv type received %u\n", tlv[0]);
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
    cprint(0, "\n");
}
