#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <ctype.h>

#include "utils.h"
#include "interface.h"
#include "tlv.h"
#include "structs/list.h"
#include "structs/hashmap.h"

typedef struct msg_queue {
    message_t *msg;
    body_t *last;
    struct msg_queue *next, *prev;
} msg_queue_t;

msg_queue_t *queue = 0;

int neighbour_eq(neighbour_t *n1, neighbour_t *n2) {
    return n1 && n2
        && memcmp(&n1->addr->sin6_addr, &n2->addr->sin6_addr, sizeof(struct in6_addr)) == 0
        && n1->addr->sin6_port == n2->addr->sin6_port;
}

int push_tlv(body_t *tlv, neighbour_t *dst) {
    pthread_mutex_lock(&queue_mutex);
    msg_queue_t *p;

    p = queue;
    if (!p) {
        goto add;
    }

    if (neighbour_eq(p->msg->dst, dst)
        && p->msg->body_length + tlv->size < p->msg->dst->pmtu) {
        goto insert;
    }

    for (p = p->next; p != queue; p = p->next) {
        if (neighbour_eq(p->msg->dst, dst) &&
            p->msg->body_length + tlv->size < p->msg->dst->pmtu) {
            goto insert;
        }
    }

 add:
    p = malloc(sizeof(msg_queue_t));
    if (!p){
        pthread_mutex_unlock(&queue_mutex);
        return -1;
    }

    p->msg = create_message(MAGIC, VERSION, 0, NULL, dst);
    if (!p->msg){
        free(p);
        pthread_mutex_unlock(&queue_mutex);
        return -2;
    }
    p->last = NULL;

    if (!queue) {
        queue = p;
        queue->next = queue;
        queue->prev = queue;
    } else {
        p->next = queue;
        p->prev = queue->prev;
        queue->prev->next = p;
        queue->prev = p;
        queue = p;
    }

 insert:
    tlv->next = NULL;
    if (p->last == NULL || p->msg->body->num > tlv->num){
        tlv->next = p->msg->body;
        p->msg->body = tlv;
        if (p->last == NULL)
            p->last = tlv;
    } else if (p->last->num < tlv->num){
        p->last->next = tlv;
        p->last = tlv;
    } else {
        body_t *b = NULL;
        for (b = p->msg->body; b->next != NULL; b++)
            if (b->next->num > tlv->num)
                break;
        if (b == NULL){ // cannot happen if everything is done as it should be
            cprint(STDERR_FILENO, "%s:%d Tried to insert a tlv but the good position could not be found.\n", __FILE__, __LINE__);
            pthread_mutex_unlock(&queue_mutex);
            free(p);
            return -3;
        }
        tlv->next = b->next;
        b->next = tlv;
    }
    p->msg->body_length += tlv->size;

    pthread_mutex_unlock(&queue_mutex);
    pthread_cond_broadcast(&send_cond);

    return 0;
}

message_t *pull_message() {
    pthread_mutex_lock(&queue_mutex);

    message_t *msg;
    msg_queue_t *q;

    if (!queue){
        pthread_mutex_unlock(&queue_mutex);
        return 0;
    }
    if (queue == queue->next) {
        msg = queue->msg;
        free(queue);
        queue = 0;
        pthread_mutex_unlock(&queue_mutex);
        return msg;
    }

    msg = queue->msg;
    q = queue;

    queue = q->next;
    queue->prev = q->prev;
    queue->prev->next = queue;

    free(q);
    pthread_mutex_unlock(&queue_mutex);
    return msg;
}


/**
 * PMTU Discovery
 */

int pmtu_discovery (body_t *tlv, neighbour_t *dst) {
    msg_queue_t *p;

    u_int16_t new_pmtu = (dst->pmtu + dst->pmtu_discovery_max) / 2;
    u_int16_t count, offset = 0, payloadlen = new_pmtu - tlv->size;
    body_t *padn = 0, *t;
    uint16_t len;
    char ipstr[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &dst->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN);

    cprint(0, "Test new pmtu of size %u with (%s,%u)\n",
           new_pmtu, ipstr, ntohs(dst->addr->sin6_port));

    count = payloadlen / 257 + (payloadlen % 257 ? 1 : 0);
    for (size_t i = 0; i < count; i++) {
        t = malloc(sizeof(body_t));
        if (!t) return -3;
        len = min(payloadlen - offset, 257);
        if (len == 1)
            t->size = tlv_pad1(&t->content);
        else
            t->size = tlv_padn(&t->content, len - 2);

        t->next = padn;
        padn = t;
        offset += t->size;
    }

    p = malloc(sizeof(msg_queue_t));
    if (!p) return -1; // free padn

    p->msg = create_message(MAGIC, VERSION, 0, 0, dst);
    if (!p->msg){
        free(p); // free padn
        return -2;
    }

    pthread_mutex_lock(&queue_mutex);

    if (!queue) {
        queue = p;
        queue->next = queue;
        queue->prev = queue;
    } else {
        p->next = queue;
        p->prev = queue->prev;
        queue->prev->next = p;
        queue->prev = p;
        queue = p;
    }

    tlv->next = padn;
    p->msg->body = tlv;
    p->msg->body_length = new_pmtu;
    p->last = NULL; // the last tlv is not null but we won't use this field here

    msg_pmtu_t *msg_pmtu = malloc(sizeof(msg_pmtu_t));
    if (!msg_pmtu) {
        pthread_mutex_unlock(&queue_mutex);
        return -1;
    }

    u_int8_t buffer[18];
    bytes_from_neighbour(dst, buffer);

    memcpy(&msg_pmtu->dataid, tlv->content + 2, 12);
    msg_pmtu->n = dst;
    msg_pmtu->pmtu = new_pmtu;
    msg_pmtu->time = time(0);

    hashmap_add(pmtu_map, buffer, msg_pmtu);
    pthread_mutex_unlock(&queue_mutex);

    return new_pmtu;
}


int decrease_pmtu() {
    time_t now = time(0);
    list_t *to_delete = 0;
    msg_pmtu_t *msg_pmtu;

    pthread_mutex_lock(&pmtu_map->mutex);

    for (size_t i = 0; i < pmtu_map->capacity; i++) {
        for (list_t *l = pmtu_map->tab[i]; l; l = l->next) {
            msg_pmtu = (msg_pmtu_t*)((map_elem*)l->val)->value;
            if (now - msg_pmtu->time > TIMEVAL_DEC_PMTU) {
                msg_pmtu->n->pmtu_discovery_max =
                    (msg_pmtu->n->pmtu + msg_pmtu->n->pmtu_discovery_max) / 2;
                cprint(0, "Decrease PMTU upper bound to %u.\n",
                       msg_pmtu->n->pmtu_discovery_max);
                list_add(&to_delete, msg_pmtu->n);
            }
        }
    }

    u_int8_t buffer[18];
    neighbour_t *n;
    while(to_delete) {
        n = list_pop(&to_delete);
        bytes_from_neighbour(n, buffer);
        hashmap_remove(pmtu_map, buffer, 1, 1);
    }

    pthread_mutex_unlock(&pmtu_map->mutex);

    return 0;
}
