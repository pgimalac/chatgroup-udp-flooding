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

unsigned int hash_neighbour(const u_int8_t *ip, u_int16_t port) {
    unsigned int hash = 5381;
    for(int i = 0; i < INET6_ADDRSTRLEN; i++, ip++)
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
