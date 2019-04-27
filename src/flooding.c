#include <stdio.h>
#include <time.h>
#include <string.h>
#include <endian.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>

#include "network.h"
#include "tlv.h"
#include "flooding.h"
#include "utils.h"
#include "structs/list.h"
#include "interface.h"
#include "utils.h"

#define MAX_TIMEOUT 30

void send_data(char *buffer, int size){
    if (buffer == 0 || size <= 0) return;

    const char *pseudo = getPseudo();
    int pseudolen = strlen(pseudo);
    if (size + pseudolen > 240){
        size = 240 - pseudolen;
        buffer[size] = '\0';
    }

    char tmp[243] = { 0 };
    snprintf(tmp, 243, "%s: %s", pseudo, buffer);

    body_t data = { 0 };
    int rc = tlv_data(&data.content, id, random_uint32(), DATA_KNOWN, tmp, pseudolen + 2 + size);

    if (rc < 0){
        if (rc == -1)
            perrorbis(STDERR_FILENO, errno, "tlv_data", STDERR_B, STDERR_F);
        else if (rc == -2)
            dprintf(logfd, "%s%sMessage too long but supposed to be cut...\n%s", LOGFD_F, LOGFD_B, RESET);
        return;
    }

    data.size = rc;

    if (flooding_add_message(data.content, data.size) != 0){
        perrorbis(STDERR_FILENO, errno, "tlv_data", STDERR_B, STDERR_F);
    }
    free(data.content);
}

void hello_potential_neighbours(struct timeval *tv) {
    int rc;
    size_t i;
    time_t max, delta, now = time(0);
    if (now == -1){
        perrorbis(STDERR_FILENO, errno, "time", STDERR_B, STDERR_F);
        return;
    }
    list_t *l;
    neighbour_t *p;
    body_t *hello;
    char ipstr[INET6_ADDRSTRLEN];

    list_t *to_delete = NULL;

    for (i = 0; i < potential_neighbours->capacity; i++) {
        for (l = potential_neighbours->tab[i]; l != NULL; l = l->next) {
            p = (neighbour_t*)l->val;

            if (p->short_hello_count >= 4) {
                assert (inet_ntop(AF_INET6, &p->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
                dprintf(logfd, "%s%sRemove (%s, %u) from potential neighbour list.\n%s", LOGFD_F, LOGFD_B,
                       ipstr, ntohs(p->addr->sin6_port), RESET);
                dprintf(logfd, "%s%sHe did not answer to short hello for too long.\n%s", LOGFD_F, LOGFD_B, RESET);

                if (list_add(&to_delete, p) == 0){
                    perrorbis(STDERR_FILENO, errno, "list_add", STDERR_F, STDERR_B);
                }
                continue;
            }

            delta = now - p->last_hello_send;
            max = 1 << (p->short_hello_count + 4);

            if (delta >= max) {
                hello = malloc(sizeof(body_t));
                if (hello == NULL){
                    perrorbis(STDERR_FILENO, errno, "malloc", STDERR_F, STDERR_B);
                    continue;
                }

                rc = tlv_hello_short(&hello->content, id);
                if (rc < 0){
                    perrorbis(STDERR_FILENO, errno, "tlv_hello_short", STDERR_F, STDERR_B);
                    free(hello);
                    continue;
                }
                hello->size = rc;

                rc = push_tlv(hello, p);
                if (rc < 0) {
                    fprintf(stderr, "%s%sCould not insert short hello into message queue\n%s", STDERR_F, STDERR_B, RESET);
                    free(hello->content);
                    free(hello);
                }
            } else if (max - delta < tv->tv_sec) {
                tv->tv_sec = max - delta;
            }
        }
    }

    while (to_delete != NULL){
        neighbour_t *n = list_pop(&to_delete);
        if (!hashset_remove_neighbour(potential_neighbours, n))
            dprintf(logfd, "%s%s%s:%d Tried to remove from a potential neighbour that wasn't one.\n%s",
                LOGFD_B, LOGFD_F, __FILE__, __LINE__, RESET);
        free(n->addr);
        free(n);
    }
}

int hello_neighbours(struct timeval *tv) {
    neighbour_t *p;
    int rc;
    size_t i, size = 0;
    time_t now = time(0), delta;
    if (now == -1){
        perrorbis(STDERR_FILENO, errno, "time", STDERR_B, STDERR_F);
        return -1;
    }
    list_t *l, *to_delete = 0;
    char ipstr[INET6_ADDRSTRLEN];
    tv->tv_sec = MAX_TIMEOUT;
    tv->tv_usec = 0;

    for (i = 0; i < neighbours->capacity; i++) {
        for (l = neighbours->tab[i]; l; l = l->next, size++) {
            p = (neighbour_t*)l->val;
            if (now - p->last_hello < 120) {
                delta = now - p->last_hello_send;
                if (delta >= MAX_TIMEOUT) {
                    body_t *hello = malloc(sizeof(body_t));
                    if (hello == NULL){
                        perrorbis(STDERR_FILENO, errno, "malloc", STDERR_F, STDERR_B);
                        continue;
                    }

                    rc = tlv_hello_long(&hello->content, id, p->id);
                    if (rc < 0){
                        perrorbis(STDERR_FILENO, errno, "tlv_hello_long", STDERR_F, STDERR_B);
                        free(hello);
                        continue;
                    }
                    hello->size = rc;

                    rc = push_tlv(hello, p);
                    if (rc < 0) {
                        fprintf(stderr, "%s%sCould not insert long hello into message queue\n%s", STDERR_F, STDERR_B, RESET);
                        free(hello->content);
                        free(hello);
                    }
                } else if (MAX_TIMEOUT - delta < tv->tv_sec) {
                    tv->tv_sec = MAX_TIMEOUT - delta;
                }
            } else if (list_add(&to_delete, p) == 0){
                perrorbis(STDERR_FILENO, errno, "list_add", STDERR_F, STDERR_B);
            }
        }
    }

    while (to_delete) {
        p = (neighbour_t*)list_pop(&to_delete);
        if (!hashset_remove(neighbours, p->addr->sin6_addr.s6_addr, p->addr->sin6_port))
            fprintf(stderr, "%s%s%s:%d Tried to remove a neighbour that wasn't actually one.\n%s",
                STDERR_B, STDERR_F, __FILE__, __LINE__, RESET);
        rc = hashset_add(potential_neighbours, p);
        if (rc == 2)
            fprintf(stderr, "%s%s%s:%d Tried to add to potentials a neighbour that was already in.\n%s",
                STDERR_B, STDERR_F, __FILE__, __LINE__, RESET);
        else if (rc == 0){
            perrorbis(STDERR_FILENO, ENOMEM, "hashset_add", STDERR_F, STDERR_B);
            free(p->addr);
            free(p);
            return -1;
        }

        assert (inet_ntop(AF_INET6, &p->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
        dprintf(logfd, "%s%sRemove (%s, %u) from neighbour list and add to potential neighbours.\n%s",
            LOGFD_F, LOGFD_B, ipstr, ntohs(p->addr->sin6_port), RESET);
        dprintf(logfd, "%s%sHe did not send long hello for too long \n%s", LOGFD_F, LOGFD_B, RESET);
    }

    return size;
}

int flooding_add_message(const u_int8_t *data, int size) {
    neighbour_t *p;
    data_info_t *dinfo;
    int now = time(0), rc;
    if (now == -1){
        perrorbis(STDERR_FILENO, errno, "time", STDERR_B, STDERR_F);
        return -1;
    }
    size_t i;
    list_t *l;
    char buffer[18];

    hashmap_t *ns = hashmap_init(18);
    if (!ns) {
        perrorbis(STDERR_FILENO, ENOMEM, "hashmap_init", STDERR_F, STDERR_B);
        return -1;
    }

    for (i = 0; i < neighbours->capacity; i++) {
        for (l = neighbours->tab[i]; l; l = l->next) {
            p = (neighbour_t*)l->val;

            dinfo = malloc(sizeof(data_info_t));
            if (!dinfo) {
                perrorbis(STDERR_FILENO, errno, "malloc", STDERR_F, STDERR_B);
                continue;
            }
            memset(dinfo, 0, sizeof(data_info_t));

            dinfo->neighbour = p;
            dinfo->time = now;

            bytes_from_neighbour(p, buffer);
            rc = hashmap_add(ns, buffer, dinfo);
            if (rc == 2)
                fprintf(stderr, "%s%sTried to add a data_info in the flooding_map but it was already in at line %d in %s.\n%s",
                    STDERR_B, STDERR_F, __LINE__, __FILE__, RESET);
            else if (rc == 0){
                perrorbis(STDERR_FILENO, ENOMEM, "hashmap_add", STDERR_F, STDERR_B);
                free(dinfo);
            }

        }
    }

    rc = hashmap_add(flooding_map, data + 2, ns);
    if (rc == 2)
        fprintf(stderr, "%s%sTried to add a map in the flooding_map but it was already in at line %d in %s.\n%s",
            STDERR_B, STDERR_F, __LINE__, __FILE__, RESET);
    else if (rc == 0)
        perrorbis(STDERR_FILENO, ENOMEM, "hashmap_add", STDERR_F, STDERR_B);
    if (rc != 1)
        hashmap_destroy(ns, 1);

    void *tmp = voidndup(data, size);
    rc = hashmap_add(data_map, data + 2, tmp);
    if (rc == 2)
        fprintf(stderr, "%s%s%s:%d Tried to add a data in data_map but it was already in.\n%s",
            STDERR_B, STDERR_F, __FILE__, __LINE__, RESET);
    else if (rc == 0)
        perrorbis(STDERR_FILENO, ENOMEM, "hashset_add", STDERR_F, STDERR_B);
    if (rc != 1)
        free(tmp);

    return 0;
}

int flooding_send_msg(const char *dataid, list_t **msg_done) {
    size_t i, size;
    int rc;
    time_t tv = MAX_TIMEOUT, delta, now = time(0);
    if (now == -1){
        perrorbis(STDERR_FILENO, errno, "time", STDERR_B, STDERR_F);
        return -1;
    }
    list_t *l;
    data_info_t *dinfo;
    body_t *body;
    char ipstr[INET6_ADDRSTRLEN];
    u_int8_t *data;
    hashmap_t *map;

    data = hashmap_get(data_map, dataid);
    if (!data){
        fprintf(stderr, "%s%s%s:%d Data_map did not contained a dataid it was supposed to contain.\n%s",
            STDERR_F, STDERR_B, __FILE__, __LINE__, RESET);
        return -1;
    }

    size = data[1] + 2;

    map = hashmap_get(flooding_map, dataid);
    if (!map){
        fprintf(stderr, "%s%s%s:%d Flooding_map did not contained a dataid it was supposed to contain.\n%s",
            STDERR_F, STDERR_B, __FILE__, __LINE__, RESET);
        return -2;
    }

    list_t *to_delete = NULL;
    for (i = 0; i < map->capacity; i++) {
        for (l = map->tab[i]; l; l = l->next) {
            dinfo = (data_info_t*)((map_elem*)l->val)->value;

            if (dinfo->send_count >= 5) {
                body = malloc(sizeof(body_t));
                rc = tlv_goaway(&body->content, GO_AWAY_HELLO,
                                       "You did not answer to data for too long.", 40);
                if (rc < 0){
                    perrorbis(STDERR_FILENO, errno, "malloc", STDERR_B, STDERR_F);
                    free(body);
                    continue;
                }
                body->size = rc;
                rc = push_tlv(body, dinfo->neighbour);
                if (rc < 0) {
                    fprintf(stderr, "%s%sCould not insert go away into message queue\n%s", STDERR_F, STDERR_B, RESET);
                    free(body->content);
                    free(body);
                }

                assert (inet_ntop(AF_INET6, &dinfo->neighbour->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
                dprintf(logfd, "%s%sRemove (%s, %u) from neighbour list and add to potential neighbours.\n%s",
                    LOGFD_F, LOGFD_B, ipstr, ntohs(dinfo->neighbour->addr->sin6_port), RESET);
                dprintf(logfd, "%s%sHe did not answer to data for too long.\n%s", LOGFD_F, LOGFD_B, RESET);

                if (hashset_remove(neighbours,
                               dinfo->neighbour->addr->sin6_addr.s6_addr,
                               dinfo->neighbour->addr->sin6_port) == NULL){
                    fprintf(stderr, "%s%s%s:%d Tried to remove a neighbour that wasn't one.\n%s",
                        STDERR_F, STDERR_B, __FILE__, __LINE__, RESET);
                }

                rc = hashset_add(potential_neighbours, dinfo->neighbour);
                if (rc == 0){
                    perrorbis(STDERR_FILENO, ENOMEM, "hashset_add", STDERR_F, STDERR_B);
                } else if (rc == 2){
                    fprintf(stderr, "%s%s%s:%d Tried to add a potential neighbour that was already one.\n%s",
                        STDERR_F, STDERR_B, __FILE__, __LINE__, RESET);
                }

                if (!list_add(&to_delete, dinfo->neighbour)){
                    perrorbis(STDERR_FILENO, errno, "list_add", STDERR_B, STDERR_F);
                }
                continue;
            }

            delta = 1UL << dinfo->send_count;

            if (delta < now - dinfo->last_send) {
                body = malloc(sizeof(body_t));
                if (!body){
                    perrorbis(STDERR_FILENO, errno, "malloc", STDERR_F, STDERR_B);
                    continue;
                }

                body->content = voidndup(data, size);
                if (!body->content) {
                    free(body);
                    perrorbis(STDERR_FILENO, errno, "malloc", STDERR_F, STDERR_B);
                    continue;
                }

                body->size = size;

                rc = push_tlv(body, dinfo->neighbour);
                if (rc < 0) {
                    fprintf(stderr, "%s%s%s:%d Could not insert data into message queue\n%s",
                        STDERR_F, STDERR_B, __FILE__, __LINE__, RESET);
                    free(body->content);
                    free(body);
                }
            }

            if (delta < tv) {
                tv = delta;
            }
        }
    }

    neighbour_t *obj;
    while ((obj = list_pop(&to_delete)) != NULL){
        assert (inet_ntop(AF_INET6, &obj->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
        dprintf(logfd, "%s%sRemove (%s, %u) from map.\n%s", LOGFD_F, LOGFD_B,
                ipstr, ntohs(obj->addr->sin6_port), RESET);

        char buf[18];
        bytes_from_neighbour(obj, buf);
        rc = hashmap_remove(map, buf, 1, 1);
        if (rc == 0)
            fprintf(stderr, "%s%s%s:%d Tried to remove a dataid from flooding map but it wasn't in.\n%s",
                STDERR_F, STDERR_B, __FILE__, __LINE__, RESET);
    }

    if (map->size == 0 && !list_add(msg_done, voidndup(dataid, 12)))
        perrorbis(STDERR_FILENO, errno, "list_add", STDERR_B, STDERR_F);

    return tv;
}

int message_flooding(struct timeval *tv) {
    size_t i;
    int rc;
    list_t *l, *msg_done = 0;
    char *dataid;
    hashmap_t *map;

    for (i = 0; i < flooding_map->capacity; i++) {
        for (l = flooding_map->tab[i]; l; l = l->next) {
            dataid = (char*)((map_elem*)l->val)->key;

            rc = flooding_send_msg(dataid, &msg_done);
            if (rc < 0) {
                continue;
            }

            if (rc < tv->tv_sec) {
                tv->tv_sec = rc;
            }
        }
    }

    while((dataid = list_pop(&msg_done)) != NULL) {
        map = hashmap_get(flooding_map, dataid);
        if (map)
            hashmap_destroy(map, 1);
        else
            fprintf(stderr, "%s%s%s:%d Tried to get a dataid from flooding map but it wasn't in.\n%s",
                STDERR_F, STDERR_B, __FILE__, __LINE__, RESET);

        if (hashmap_remove(data_map, dataid, 1, 1) == 0)
            fprintf(stderr, "%s%s%s:%d Tried to remove a dataid from data map but it wasn't in.\n%s",
                STDERR_F, STDERR_B, __FILE__, __LINE__, RESET);

        if (hashmap_remove(flooding_map, dataid, 1, 0) == 0)
            fprintf(stderr, "%s%s%s:%d Tried to remove a dataid from flooding map but it wasn't in.\n%s",
                STDERR_F, STDERR_B, __FILE__, __LINE__, RESET);

        free(dataid);
    }

    return 0;
}

int send_neighbour_to(neighbour_t *p) {
    size_t i;
    int rc;
    list_t *l;
    neighbour_t *a;
    body_t *body;
    char ipstr[INET6_ADDRSTRLEN];

    for (i = 0; i < neighbours->capacity; i++) {
        for (l = neighbours->tab[i]; l; l = l->next) {
            a = (neighbour_t*)l->val;
            body = malloc(sizeof(body_t));
            if (!body){
                perrorbis(STDERR_FILENO, errno, "malloc", STDERR_F, STDERR_B);
                continue;
            }

            rc = tlv_neighbour(&body->content,
                                      &a->addr->sin6_addr,
                                      a->addr->sin6_port);
            if (rc < 0){
                free(body);
                perrorbis(STDERR_FILENO, errno, "malloc", STDERR_F, STDERR_B);
                continue;
            }

            rc = push_tlv(body, p);
            if (rc < 0) {
                fprintf(stderr, "%s%s%s:%d Could not insert data into message queue\n%s",
                    STDERR_F, STDERR_B, __FILE__, __LINE__, RESET);
                free(body->content);
                free(body);
            }
        }
    }

    assert (inet_ntop(AF_INET6, &p->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
    dprintf(logfd, "%s%sSend neighbours to (%s, %u).\n%s", LOGFD_F, LOGFD_B,
            ipstr, ntohs(p->addr->sin6_port), RESET);

    return 0;
}

void neighbour_flooding(short force) {
    size_t i;
    time_t now = time(0);
    if (now == -1){
        perrorbis(STDERR_FILENO, errno, "time", STDERR_B, STDERR_F);
        return;
    }

    list_t *l;
    neighbour_t *p;

    for (i = 0; i < neighbours->capacity; i++) {
        for (l = neighbours->tab[i]; l; l = l->next) {
            p = (neighbour_t*)l->val;
            if (force || now - p->last_neighbour_send > 120) {
                send_neighbour_to(p);
            }
        }
    }
}
