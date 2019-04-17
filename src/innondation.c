#include <stdio.h>
#include <time.h>
#include <string.h>
#include <endian.h>
#include <arpa/inet.h>

#include "types.h"
#include "network.h"
#include "tlv.h"
#include "innondation.h"
#include "utils.h"
#include "structs/list.h"

#define MAX_TIMEOUT 30

void hello_potential_neighbours() {
    int rc, i;
    list_t *l;
    neighbour_t *p;
    body_t *hello;

    for (i = 0; i < potential_neighbours->capacity; i++) {
        for (l = potential_neighbours->tab[i]; l; l = l->next) {
            p = (neighbour_t*)l->val;
            hello = malloc(sizeof(body_t));
            hello->size = tlv_hello_short(&hello->content, id);
            rc = push_tlv(hello, p);
            if (rc < 0) {
                fprintf(stderr, "Could not insert short hello into message queue\n");
            }
        }
    }
}

int hello_neighbours(struct timeval *tv) {
    neighbour_t *p;
    int i, rc, size = 0;
    time_t now = time(0), delta;
    list_t *l;
    tv->tv_sec = MAX_TIMEOUT;
    tv->tv_usec = 0;

    for (i = 0; i < neighbours->capacity; i++) {
        for (l = neighbours->tab[i]; l; l = l->next, size++) {
            p = (neighbour_t*)l->val;
            if (now - p->last_hello < 120) {
                delta = now - p->last_hello_send;
                if (delta >= 30) {
                    body_t *hello = malloc(sizeof(body_t));
                    hello->size = tlv_hello_long(&hello->content, id, p->id);
                    rc = push_tlv(hello, p);
                    if (rc < 0) {
                        fprintf(stderr, "Could not insert long hello into message queue\n");
                    }
                } else if (MAX_TIMEOUT - delta < tv->tv_sec) {
                    tv->tv_sec = MAX_TIMEOUT - delta;
                }
            }
        }
    }

    printf("Timeout before next send loop %ld.\n", tv->tv_sec);

    return size;
}
