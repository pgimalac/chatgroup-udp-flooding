#include <stdio.h>
#include <time.h>
#include <string.h>
#include <endian.h>
#include <arpa/inet.h>

#include "network.h"
#include "tlv.h"
#include "innondation.h"
#include "utils.h"
#include "structs/list.h"
#include "pseudo.h"

#define MAX_TIMEOUT 30

void send_data(const char *buffer, int size){
    char tmp[521] = { 0 }, dataid[12];
    body_t *data;

    if (buffer == 0 || size <= 0) return;

    snprintf(tmp, 511, "%s: %s", getPseudo(), buffer);

    data = malloc(sizeof(body_t));
    data->size = tlv_data(&data->content, id, random_uint32(), 0, tmp, strlen(tmp));

    memcpy(dataid, data->content + 2, 12);

    //TODO handle errors
    innondation_add_message(data->content, data->size);
    free(data->content);
    free(data);
}

void hello_potential_neighbours(struct timeval *tv) {
    int rc, i;
    time_t max, delta, now = time(0);
    list_t *l;
    neighbour_t *p;
    body_t *hello;
    char ipstr[INET6_ADDRSTRLEN];

    list_t *to_delete = NULL;

    for (i = 0; i < potential_neighbours->capacity; i++) {
        for (l = potential_neighbours->tab[i]; l != NULL; l = l->next) {
            p = (neighbour_t*)l->val;

            if (p->short_hello_count >= 2) {
                if (inet_ntop(AF_INET6,
                              &p->addr->sin6_addr,
                              ipstr, INET6_ADDRSTRLEN) == 0){
                    perror("inet_ntop");
                } else {
                    printf("Remove (%s, %u) from potential neighbour list.\n",
                           ipstr, ntohs(p->addr->sin6_port));
                    printf("He did not answer to short hello for too long.\n");
                }

                list_add(&to_delete, p);
                continue;
            }

            delta = now - p->last_hello_send;
            max = 1 << (p->short_hello_count + 4);

            if (delta >= max) {
                hello = malloc(sizeof(body_t));
                hello->size = tlv_hello_short(&hello->content, id);
                rc = push_tlv(hello, p);
                if (rc < 0) {
                    fprintf(stderr, "Could not insert short hello into message queue\n");
                }
            } else if (max - delta < tv->tv_sec) {
                tv->tv_sec = max - delta;
            }
        }
    }

    while (to_delete != NULL){
        neighbour_t *n = list_pop(&to_delete);
        hashset_remove_neighbour(potential_neighbours, n);
        free(n->addr);
        free(n);
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

    return size;
}

int innondation_add_message(const char *data, int size) {
    neighbour_t *p;
    data_info_t *dinfo;
    int now = time(0);
    int i;
    list_t *l;
    char *dataid, *datacopy;

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
            memset(dinfo, 0, sizeof(data_info_t));

            dinfo->neighbour = p;
            dinfo->time = now;

            hashmap_add(ns, p, dinfo);
        }
    }

    dataid = voidndup(data + 2, 12);
    datacopy = voidndup(data, size);

    hashmap_add(innondation_map, dataid, ns);
    hashmap_add(data_map, dataid, datacopy);
    free(dataid);

    return 0;
}

int innondation_send_msg(const char *dataid) {
    size_t i, size, count = 0;
    time_t tv = MAX_TIMEOUT, delta, now = time(0);
    list_t *l;
    data_info_t *dinfo;
    body_t *body;
    char ipstr[INET6_ADDRSTRLEN], *data;
    hashmap_t *map;

    data = hashmap_get(data_map, dataid);
    if (!data) return -1;

    size = data[1] + 2;

    map = hashmap_get(innondation_map, dataid);
    if (!map) return -2;

    list_t *to_delete = NULL;
    for (i = 0; i < map->capacity; i++) {
        for (l = map->tab[i]; l; l = l->next) {
            dinfo = (data_info_t*)((map_elem*)l->val)->value;
            count++;

            if (dinfo->send_count >= 2) {
                body = malloc(sizeof(body_t));
                body->size = tlv_goaway(&body->content, GO_AWAY_HELLO,
                                       "You did not answer to data for too long.", 40);
                push_tlv(body, dinfo->neighbour);

                if (inet_ntop(AF_INET6,
                              &dinfo->neighbour->addr->sin6_addr,
                              ipstr, INET6_ADDRSTRLEN) == 0){
                    perror("inet_ntop");
                } else {
                    printf("Remove (%s, %u) from neighbour list and add to potential neighbours.\n", ipstr, ntohs(dinfo->neighbour->addr->sin6_port));
                    printf("He did not answer to data for too long.\n");
                }

                hashset_remove(neighbours,
                               dinfo->neighbour->addr->sin6_addr.s6_addr,
                               dinfo->neighbour->addr->sin6_port);
                hashset_add(potential_neighbours, dinfo->neighbour);

                list_add(&to_delete, dinfo->neighbour);
                continue;
            }

            delta = 1UL << dinfo->send_count;

            if (delta < now - dinfo->last_send) {
                body = malloc(sizeof(body_t));
                if (!body) continue;

                body->content = voidndup(data, size);
                if (!body->content) {
                    free(body);
                    continue;
                }

                body->size = size;
                push_tlv(body, dinfo->neighbour);
            }

            if (delta < tv) {
                tv = delta;
            }
        }
    }

    while (to_delete != NULL){
        neighbour_t *obj = list_pop(&to_delete);
        hashmap_remove(map, obj, 1);
    }

    if (count == 0) {
        hashmap_remove(data_map, dup, 1);
        hashmap_remove(innondation_map, dup, 1);
    }

    return tv;
}

int message_innondation(struct timeval *tv) {
    size_t i;
    int rc;
    list_t *l;
    char *dataid;

    for (i = 0; i < innondation_map->capacity; i++) {
        for (l = innondation_map->tab[i]; l; l = l->next) {
            dataid = (char*)((map_elem*)l->val)->key;

            rc = innondation_send_msg(dataid);
            if (rc < 0) {
                continue;
            }

            if (rc < tv->tv_sec) {
                tv->tv_sec = rc;
            }
        }
    }

    return 0;
}
