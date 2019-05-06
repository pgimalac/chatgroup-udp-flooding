#include <stdio.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#include "types.h"
#include "network.h"
#include "tlv.h"
#include "flooding.h"
#include "interface.h"
#include "websocket.h"

static void handle_pad1(const u_int8_t *tlv, neighbour_t *n) {
    cprint(0, "Pad1 received\n");
}

static void handle_padn(const u_int8_t *tlv, neighbour_t *n) {
    cprint(0, "Padn of length %u received\n", tlv[1]);
}

static void handle_hello(const u_int8_t *tlv, neighbour_t *n){
    time_t now = time(0);
    assert(now != -1);
    int rc, is_long = tlv[1] == 16;

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

        rc = hashset_add(neighbours, n);
        if (rc == 2)
            cprint(STDERR_FILENO, "%s:%d Tried to add to potentials a neighbour that was already in.\n",
                __FILE__, __LINE__);
        else if (rc == 0){
            perrorbis(ENOMEM, "hashset_add");
            free(n->addr);
            free(n->tutor_id);
            free(n);
            return;
        }
        if (!hashset_remove(potential_neighbours, n->addr->sin6_addr.s6_addr, n->addr->sin6_port))
            cprint(STDERR_FILENO, "%s:%d Tried to remove a neighbour that wasn't one.\n",
                __FILE__, __LINE__);
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

    if (!map && !hashmap_contains(data_map, (void*)(tlv + 2))) {
        if (tlv[14] == 0) {
            cprint(0, "New message received.\n");
            print_message((u_int8_t*)tlv + 15, size);
            print_web(tlv + 15, size);
        } else if (tlv[14] == DATA_FRAG) {
            if (size < 9)
                cprint(0, "Data fragment was corrupted (too short).\n");

            char fragid[12] = { 0 };
            memcpy(fragid, tlv + 2, 8);
            memcpy(fragid + 8, tlv + 15, 4);
            frag_t *frag = hashmap_get(fragmentation_map, fragid);
            if (!frag) {
                frag = malloc(sizeof(frag_t));
                if (!frag){
                    cperror("malloc");
                    return;
                }
                frag->id = voidndup(fragid, 12);
                if (!frag->id){
                    cperror("malloc");
                    free(frag);
                    return;
                }

                memcpy(&frag->type, tlv + 19, 1);
                memcpy(&frag->size, tlv + 20, 2);
                frag->size = ntohs(frag->size);

                cprint(0, "New fragment of total size %u\n", frag->size);
                frag->recv = 0;

                frag->buffer = malloc(frag->size);
                if (!frag->buffer){
                    free(frag->id);
                    free(frag);
                    return;
                }
                rc = hashmap_add(fragmentation_map, fragid, frag);
                if (rc == 2)
                    cprint(STDERR_FILENO, "%s:%d Tried to add to fragmentation_map an id that was already in.\n",
                        __FILE__, __LINE__);
                else if (rc == 0)
                    perrorbis(ENOMEM, "hashset_add");
                if (rc != 1){
                    free(frag->id);
                    free(frag->buffer);
                    free(frag);
                    return;
                }
            }

            uint16_t fragpos, fragsize;
            memcpy(&fragpos, tlv + 22, 2);
            fragpos = ntohs(fragpos);
            fragsize = tlv[1] - 22;

            frag->recv += fragsize;
            frag->last = time(0);
            assert(frag->last != -1);
            memcpy(frag->buffer + fragpos, tlv + 24, fragsize);

            if (frag->recv == frag->size) {
                cprint(0, "New long message received.\n");
                print_file(tlv[19], frag->buffer, frag->size);
                free(frag->buffer);
                free(frag->id);
                if (!hashmap_remove(fragmentation_map, fragid, 1, 1))
                    cprint(STDERR_FILENO, "%s:%d Tried to remove an id from fragmentation_map that wasn't in.\n",
                        __FILE__, __LINE__);
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
    nonce_t nonce = *(nonce_t*)(tlv + 10);
    body = malloc(sizeof(body_t));
    if (!body)
        return;
    rc = tlv_ack(&body->content, sender, nonce);
    if (rc < 0){
        perrorbis(ENOMEM, "tlv_ack");
        free(body);
        return;
    }

    body->size = rc;
    body->next = NULL;

    push_tlv(body, n);

    if (map){
        bytes_from_neighbour(n, buffer);
        hashmap_remove(map, buffer, 1, 1);
    }
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
    if (!datime)
        cprint(STDERR_FILENO, "%s:%d Tried to get a tlv from data_map but it wasn't in.\n", __FILE__, __LINE__);
    else {
        datime->last = time(0);
        assert(datime->last != -1);

    }

    bytes_from_neighbour(n, buffer);
    data_info_t *dinfo = hashmap_get(map, buffer);
    if (!dinfo) {
        cprint(0, "Not necessary ack\n");
        return;
    }

    if (n->pmtu < dinfo->pmtu_discover) {
        cprint(0, "Upgrade PMTU for this neighbour to %u\n", dinfo->pmtu_discover);
        n->pmtu = dinfo->pmtu_discover;
        n->pmtu_discovery_max = n->pmtu << 1;
    }

    hashmap_remove(map, buffer, 1, 1);
}

static void handle_goaway(const u_int8_t *tlv, neighbour_t *n){
    char ipstr[INET6_ADDRSTRLEN];
    assert (inet_ntop(AF_INET6, &n->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
    cprint(0, "Go away from (%s, %u).\n", ipstr, ntohs(n->addr->sin6_port));

    switch(tlv[2]) {
    case GO_AWAY_UNKNOWN:
        cprint(0, "Asked you to go away for an unknown reason.\n");
        break;
    case GO_AWAY_LEAVE:
        cprint(0, "He left the network.\n");
        break;
    case GO_AWAY_HELLO:
        cprint(STDERR_FILENO, "You did not send long hello or data for too long.\n");
        break;
    case GO_AWAY_BROKEN:
        cprint(STDERR_FILENO, "You broke the protocol.\n");
        break;
    }

    if (tlv[1] > 1)
        cprint(0, "Go away message: %*s\n", tlv[1] - 1, tlv + 3);

    if (hashset_remove(neighbours, n->addr->sin6_addr.s6_addr, n->addr->sin6_port))
        cprint(0, "Remove %lx from friends.\n", n->id);
    else
        cprint(0, "Received a goaway from someone that wasn't a friend.\n");

    int rc = hashset_add(potential_neighbours, n);
    if (rc == 2)
        cprint(STDERR_FILENO, "%s:%d Tried to add a neighbour to potentials but it was already in.\n",
            __FILE__, __LINE__);
    else if (rc == 0)
        perrorbis(ENOMEM, "hashset_add");
    else
        cprint(0, "Add (%s, %u) to potential friends\n", ipstr, ntohs(n->addr->sin6_port));
}

static void handle_warning(const u_int8_t *tlv, neighbour_t *n){
    if (tlv[1] == 0) {
        cprint(0, "Receive empty warning.\n");
        return;
    }

    cprint(0, "Warning: %*s\n", tlv[1], tlv + 2);
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

void handle_invalid_message(int rc, neighbour_t *n){
    if (!hashset_contains(neighbours, n->addr->sin6_addr.s6_addr, n->addr->sin6_port))
        return;
    if (rc == 0 || rc == -8 || rc == -10){ // our mistake
        if (rc == -8)
            cprint(STDERR_FILENO, "Call bytes_to_message with a NULL argument.\n");
        else if (rc == -10)
            cprint(STDERR_FILENO, "Memory error when reading a received message.\n");
        else
            cprint(STDERR_FILENO, "handle_invalid_message was called with an error code of 0.\n");
        return;
    }
    int size;
    body_t *msg = malloc(sizeof(body_t));
    char *string = NULL;
    memset(msg, 0, sizeof(body_t));
    if (rc == -9){ // warning
        string = "You sent an empty message.";

        size = tlv_warning(&msg->content, string, strlen(string));
        if (size < 0){
            free(msg);
            return;
        }
        msg->size = size;
    } else if (rc == BUFSH || rc == BUFINC || rc == SUMLONG ||
                PADNO0 || HELLOSIZEINC || NEIGSIZEINC ||
                DATASIZEINC || ACKSIZEINC || GOAWSIZEINC) { // goaway
        switch (rc) {
            case BUFSH:
                string = "You sent me less than four bytes.";
                break;
            case BUFINC:
                string = "You sent me a message whose size is longer than the number of received bytes.";
                break;
            case SUMLONG:
                string = "You sent a message in which the sum of the sizes of the tlv is greater than the size in the message.";
                break;
            case PADNO0:
                string = "You sent a pad which wasn't filled by zero-bytes.";
                break;
            case HELLOSIZEINC:
                string = "You sent a hello whose size was neither 8 nor 16.";
                break;
            case NEIGSIZEINC:
                string = "You sent a neighbour whose size wasn't 18.";
                break;
            case DATASIZEINC:
                string = "You sent a data whose size was less than 13.";
                break;
            case ACKSIZEINC:
                string = "You sent an ack whose size was less not 12.";
                break;
            case GOAWSIZEINC:
                string = "You sent a goaway whose size was 0.";
                break;
            default:
                assert(0);
        }

        char ipstr[INET6_ADDRSTRLEN];
        size = tlv_goaway(&msg->content, GO_AWAY_BROKEN, string, strlen(string));
        if (size < 0){
            free(msg);
            return;
        }
        msg->size = size;
        assert (inet_ntop(AF_INET6, &n->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
        cprint(0, "Remove (%s, %u) from neighbour list and add to potential neighbours.\n",
            ipstr, ntohs(n->addr->sin6_port));

        if (hashset_remove(neighbours,
                       n->addr->sin6_addr.s6_addr,
                       n->addr->sin6_port) == NULL){
            cprint(STDERR_FILENO, "%s:%d Tried to remove a neighbour that wasn't one.\n",
                __FILE__, __LINE__);
        }

        rc = hashset_add(potential_neighbours, n);
        if (rc == 0)
            perrorbis(ENOMEM, "hashset_add");
        else if (rc == 2){
            cprint(STDERR_FILENO, "%s:%d Tried to add a potential neighbour that was already one.\n",
                __FILE__, __LINE__);
        }
    } else {
        cprint(STDERR_FILENO, "Weird error code given to handle_invalid_message.\n");
        free(msg);
        return;
    }
    cprint(STDERR_FILENO, "Sent: %s\n", string);
    push_tlv(msg, n);
}

void handle_tlv(const body_t *tlv, neighbour_t *n) {
    do {
        if (tlv->content[0] >= NUMBER_TLV_TYPE) {
            handlers[NUMBER_TLV_TYPE](tlv->content, n);
        } else if (n->status == NEIGHBOUR_SYM ||
                   (n->status == NEIGHBOUR_POT && tlv->content[0] == BODY_HELLO)) {
            handlers[tlv->content[0]](tlv->content, n);
        }
    } while ((tlv = tlv->next) != NULL);
    cprint(0, "\n");
}
