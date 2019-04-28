#include <time.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>

#include "utils.h"
#include "interface.h"

void* voidndup(const void *o, int n){
    if (n <= 0) return NULL;
    void *cpy = malloc(n);

    if (cpy != NULL)
        memcpy(cpy, o, n);

    return cpy;
}

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

unsigned int hash_neighbour_data(const u_int8_t ip[16], u_int16_t port) {
    unsigned int hash = 5381;
    for(int i = 0; i < 16; i++)
        hash = ((hash << 5) + hash) + ip[i] + port;
    return hash;
}

unsigned int hash_key(const char *buffer, int keylen) {
    unsigned int hash = 5381;

    for (int i = 0; i < keylen; i++)
        hash = ((hash << 5) + hash) + buffer[i];

    return hash;
}

void free_message(message_t *msg) {
    if (!msg) return;

    body_t *p, *b;
    p = msg->body;

    while (p != NULL) {
        b = p;
        p = p->next;

        free(b->content);
        free(b);
    }

    free(msg);
}

typedef struct msg_queue {
    message_t *msg;
    struct msg_queue *next, *prev;
} msg_queue_t;

msg_queue_t *queue = 0;

int neighbour_eq(neighbour_t *n1, neighbour_t *n2) {
    return n1 && n2
        && memcmp(&n1->addr->sin6_addr, &n2->addr->sin6_addr, sizeof(struct in6_addr)) == 0
        && n1->addr->sin6_port == n2->addr->sin6_port;
}

int push_tlv(body_t *tlv, neighbour_t *dst) {
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
    if (!p) return -1;

    p->msg = create_message(MAGIC, VERSION, 0, 0, dst);
    if (!p->msg){
        free(p);
        return -2;
    }

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

message_t *create_message(u_int8_t m, u_int8_t v, u_int16_t s, body_t* b, neighbour_t* n){
    message_t *message = malloc(sizeof(message_t));

    if (message){
        message->magic = m;
        message->version = v;
        message->body_length = s;
        message->body = b;
        message->dst = n;
    }

    return message;
}

char *strappl(char* str1, ...){
    if (!str1) return NULL;

    va_list ap;
    va_start(ap, str1);

    int* tmp = alloca(sizeof(int));
    *tmp = strlen(str1);
    list_t *head = list_init(tmp, NULL), *tail = head;
    int l = *tmp + 1;
    char* st;
    while ((st = va_arg(ap, char*))){
        tmp = alloca(sizeof(int));
        *tmp = strlen(st);
        l += *tmp;
        tail->next = list_init(tmp, NULL);
        tail = tail->next;
    }
    va_end(ap);

    char* buff = malloc(sizeof(char) * l);
    va_start(ap, str1);
    l = 0;
    st = str1;
    do {
        strcpy(buff + l, st);
        l += *(int*)head->val;
        tail = head;
        head = head->next;
        free(tail);
    } while ((st = va_arg(ap, char*)));

    va_end(ap);
    return buff;
}

char *strappv(char** str){
    if (!str || !str[0]) return NULL;
    int *tmp = alloca(sizeof(int));
    *tmp = strlen(str[0]);
    int l = *tmp + 1;
    list_t* head = list_init(tmp, NULL), *tail = head;

    for(char** st = str + 1; *st; st++){
        tmp = alloca(sizeof(int));
        *tmp = strlen(*st);
        tail->next = list_init(tmp, NULL);
        tail = tail->next;
        l += *tmp;
    }

    char* buff = malloc(sizeof(char) * l);
    l = 0;
    for (char** st = str; *st; st++){
        strcpy(buff + l, *st);
        l += *(int*)head->val;
        tail = head;
        head = head->next;
        free(tail);
    }
    return buff;
}

void print_bytes(const char *buffer, size_t len) {
    if (!buffer) return;

    for (size_t i = 0; i < len; i++) {
        printf("%02hhx ", buffer[i]);
        if ((i + 1) % 4 == 0) printf("\n");
    }
    printf("\n");
}

void bytes_from_neighbour(const neighbour_t *n, u_int8_t buffer[18]) {
    memcpy(buffer, n->addr->sin6_addr.s6_addr, 16);
    memcpy(buffer + 16, &n->addr->sin6_port, 2);
}

void perrorbis(int fd, int err, char *str, char *B, char *F){
    dprintf(fd, "%s%s%s: %s\n%s", B, F, str, strerror(err), RESET);
}
