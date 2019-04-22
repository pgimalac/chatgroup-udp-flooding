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

    dprintf(logfd, "Timeout before next send loop %ld.\n", tv->tv_sec);

    return size;
}

int innondation_add_message(const char *data, int size) {
    neighbour_t *p;
    data_info_t *dinfo;
    int now = time(0);
    int i;
    list_t *l;
    char *dataid;

    hashmap_t *ns = hashmap_init(sizeof(neighbour_t),
                                 (unsigned int(*)(const void*))hash_neighbour);
    if (!ns) {
        return -1;
    }

    for (i = 0; i < neighbours->capacity; i++) {
        for (l = neighbours->tab[i]; l; l = l->next) {
            p = (neighbour_t*)l->val;

            dinfo = malloc(sizeof(data_info_t));
            if (!dinfo) {
                continue;
            }

            dinfo->neighbour = p;
            dinfo->send_count = 0;
            dinfo->time = now;

            hashmap_add(ns, p, dinfo, 1);
        }
    }

    dataid = malloc(12);
    memmove(dataid, data + 2, 12);

    hashmap_add(innondation_map, dataid, ns, 1);

    return 0;
}

int innondation_send_msg(const char *data, int size) {
    int i;
    list_t *l;
    data_info_t *dinfo;
    body_t *body;
    char ipstr[INET6_ADDRSTRLEN], *dataid;
    hashmap_t *map;

    dataid = malloc(12);
    memcpy(dataid, data + 2, 12);

    map = hashmap_get(innondation_map, dataid);
    free(dataid);

    if (!map) return -1;

    for (i = 0; i < map->capacity; i++) {
        for (l = map->tab[i]; l; l = l->next) {
            dinfo = (data_info_t*)l->val;

            // dont work
            /* if (++dinfo->send_count > 5) { */
            /*     body = malloc(sizeof(body_t)); */
            /*     body->size = tlv_goaway(&body->content, GO_AWAY_HELLO, */
            /*                            "You did not answer to data for too long.", 40); */
            /*     push_tlv(body, dinfo->neighbour); */

            /*     hashset_remove(neighbours, */
            /*                    dinfo->neighbour->addr->sin6_addr.s6_addr, */
            /*                    dinfo->neighbour->addr->sin6_port); */
            /*     hashset_add(potential_neighbours, dinfo->neighbour); */

            /*     if (inet_ntop(AF_INET6, */
            /*                   &dinfo->neighbour->addr->sin6_addr, */
            /*                   ipstr, INET6_ADDRSTRLEN) == 0){ */
            /*         perror("inet_ntop"); */
            /*     } else { */
            /*         printf("Remove (%s, %u) from neighbour list and add to potential neighbours. He did not answer to data for too long.\n", ipstr, htons(dinfo->neighbour->addr->sin6_port)); */
            /*     } */

            /*     continue; */
            /* } */

            body = malloc(sizeof(body_t));
            if (!body) continue;

            body->content = malloc(size);
            if (!body->content) {
                free(body);
                continue;
            }

            memcpy(body->content, data, size);
            body->size = size;
            push_tlv(body, dinfo->neighbour);
        }
    }

    return 0;
}
