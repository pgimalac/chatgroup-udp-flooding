#include "utils.h"

#include <time.h>
#include <stdio.h>
#include <arpa/inet.h>

int init_random() {

    int seed = time(0);
    if (seed == -1) return -1;

    srand(seed);
    return 0;
}

u_int64_t random_uint64 () {
    static const char rand_max_size = __builtin_ctz(~RAND_MAX);
    // change for other compilers compatibility ?
    // RAND_MAX = 2 ^ rand_max_size

    u_int64_t r = rand();
    for (int i = 64; i > 0; i -= rand_max_size)
        r = (r << rand_max_size) + rand();

    return r;
}

u_int32_t random_uint32 () {
    static const char rand_max_size = __builtin_ctz(~RAND_MAX);
    // change for other compilers compatibility ?
    // RAND_MAX = 2 ^ rand_max_size

    u_int32_t r = rand();
    for (int i = 32; i > 0; i -= rand_max_size)
        r = (r << rand_max_size) + rand();

    return r;
}

unsigned int hash_neighbour(const u_int8_t ip[16], u_int16_t port) {
    unsigned int hash = 5381;
    for(int i = 0; i < 16; i++, ip++)
        hash = ((hash << 5) + hash) + *ip + port;
    return hash;
}

unsigned int hash(const char *s) {
    unsigned int hash = 5381;
    int c;
    while ((c = *s++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

void free_message(message_t *msg, short free_body) {
    body_t *p, *b;

    if (!msg) return;

    p = msg->body;

    while (p != NULL) {
        b = p;
        p = p->next;

        free(b->content);
        if (free_body & FREE_BODY)
            free(b);
    }
}

typedef struct msg_queue {
    message_t *msg;
    struct msg_queue *next, *prev;
} msg_queue_t;

msg_queue_t *queue = 0;

int push_tlv(body_t *tlv, neighbour_t *dst) {
    msg_queue_t *p;
    int add = 0;

    p = queue;
    if (queue && dst != p->msg->dst && p->msg->body_length + tlv->size < p->msg->dst->pmtu) {
        for (; p && p->next != queue; p = p->next) {
            if (p->msg->dst == dst && p->msg->body_length + tlv->size < p->msg->dst->pmtu) {
                add = 1;
                break;
            }
        }
    } else add = (queue != 0);

    if (!add) {
        p = malloc(sizeof(msg_queue_t));
        if (!p) return -1;

        p->msg = malloc(sizeof(message_t));
        if (!p) return -2;

        p->msg->magic = 93;
        p->msg->version = 2;
        p->msg->body_length = 0;
        p->msg->body = 0;
        p->msg->dst = dst;


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
    }

    tlv->next = p->msg->body;
    p->msg->body = tlv;
    p->msg->body_length += tlv->size;

    return 0;
}

message_t *pull_message() {
    message_t *msg;
    msg_queue_t *q;

    if (!queue) return 0;
    if (queue == queue->next) {
        msg = queue->msg;
        free(queue);
        queue = 0;
        return msg;
    }

    msg = queue->msg;
    q = queue;

    queue = q->next;
    queue->prev = q->prev;
    queue->prev->next = queue;

    free(q);
    return msg;
}
