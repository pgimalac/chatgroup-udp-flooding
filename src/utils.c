#include <stdlib.h>
#include <time.h>

#include "types.h"
#include "utils.h"

int
init_random() {
    int seed = time(0);
    if (seed == -1) return -1;

    srand(seed);
    return 0;
}

u_int64_t
random_uint64 () {
    unsigned int r1 = rand(), r2 = rand();
    u_int64_t id = r1;
    id = (id << 31) + r2;
    return id;
}

u_int32_t
random_uint32 () {
    unsigned int r = rand();
    return r;
}

void
free_message(message_t *msg) {
    body_t *b, *p;

    if (!msg) return;

    p = msg->body;

    while (p) {
        b = p;
        p = p->next;

        free(b->content);
        free(b);
    }

    free(msg);
}
