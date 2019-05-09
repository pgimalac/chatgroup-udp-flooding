#include <stdio.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>

#include <sys/stat.h>
#include <fcntl.h>

#include "network.h"
#include "tlv.h"
#include "flooding.h"
#include "utils.h"
#include "structs/list.h"
#include "interface.h"
#include "utils.h"

body_t *create_body(){
    body_t *b = malloc(sizeof(body_t));
    memset(b, 0, sizeof(body_t));
    pthread_mutex_lock(&globalnum_mutex);
    b->num = globalnum++;
    pthread_mutex_unlock(&globalnum_mutex);
    return b;
}

int flooding_add_message(const u_int8_t *data, int size, int user) {
    neighbour_t *p;
    data_info_t *dinfo;
    time_t now = time(0);
    int rc;

    u_int8_t buffer[18];

    hashmap_t *ns = hashmap_init(18);
    if (!ns) {
        perrorbis(ENOMEM, "hashmap_init");
        return -1;
    }

    pthread_mutex_lock(&neighbours->mutex);

    for (size_t i = 0; i < neighbours->capacity; i++) {
        for (list_t *l = neighbours->tab[i]; l; l = l->next) {
            p = (neighbour_t*)l->val;

            dinfo = malloc(sizeof(data_info_t));
            if (!dinfo) {
                cperror("malloc");
                continue;
            }
            memset(dinfo, 0, sizeof(data_info_t));

            dinfo->neighbour = p;
            if (user)
                dinfo->time = now;
            else
                dinfo->time = now + rand() % 2;

            bytes_from_neighbour(p, buffer);
            rc = hashmap_add(ns, buffer, dinfo);
            if (rc == 2)
                cprint(STDERR_FILENO, "Tried to add a data_info in the flooding_map but it was already in at line %d in %s.\n",
                    __LINE__, __FILE__);
            else if (rc == 0){
                perrorbis(ENOMEM, "hashmap_add");
                free(dinfo);
            }

        }
    }
    pthread_mutex_unlock(&neighbours->mutex);

    datime_t *datime = malloc(sizeof(datime_t));
    datime->data = voidndup(data, size);
    datime->last = now;

    pthread_mutex_lock(&data_map->mutex);
    rc = hashmap_add(data_map, data + 2, datime);
    if (rc == 2)
        cprint(STDERR_FILENO, "%s:%d Tried to add a data in data_map but it was already in.\n",
            __FILE__, __LINE__);
    else if (rc == 0)
        perrorbis(ENOMEM, "hashset_add");

    rc = hashmap_add(flooding_map, data + 2, ns);
    if (rc == 2)
        cprint(STDERR_FILENO, "%s:%d Tried to add a map in the flooding_map but it was already in.\n",
            __FILE__, __LINE__);
    else if (rc == 0)
        perrorbis(ENOMEM, "hashmap_add");
    if (rc != 1)
        hashmap_destroy(ns, 1);
    pthread_mutex_unlock(&data_map->mutex);

    return 0;
}

static int flooding_send_msg(const char *dataid, list_t **msg_done) {
    int rc;
    time_t tv = MAX_TIMEOUT, delta, now = time(0);

    list_t *l, *to_delete = NULL;
    data_info_t *dinfo;

    body_t *body;
    char ipstr[INET6_ADDRSTRLEN];

    datime_t *datime = hashmap_get(data_map, dataid);
    if (!datime) {
        cprint(STDERR_FILENO, "%s:%d Data_map did not contained a dataid it was supposed to contain.\n",
            __FILE__, __LINE__);
        return -1;
    }

    datime->last = now;
    u_int8_t *data = datime->data;
    size_t size = data[1] + 2;

    hashmap_t *map = hashmap_get(flooding_map, dataid);
    if (!map){
        cprint(STDERR_FILENO, "%s:%d Flooding_map did not contained a dataid it was supposed to contain.\n",
            __FILE__, __LINE__);
        return -2;
    }

    pthread_mutex_lock(&map->mutex);
    for (size_t i = 0; i < map->capacity; i++) {
        for (l = map->tab[i]; l; l = l->next) {
            dinfo = (data_info_t*)((map_elem*)l->val)->value;

            if (!hashset_get(neighbours,
                            dinfo->neighbour->addr->sin6_addr.s6_addr,
                            dinfo->neighbour->addr->sin6_port)) {
                list_add(&to_delete, dinfo->neighbour);
                continue;
            }

            if (now >= dinfo->time && dinfo->send_count >= 5) {
                body = create_body();
                rc = tlv_goaway(&body->content, GO_AWAY_HELLO,
                                       "You did not answer to data for too long.", 40);
                if (rc < 0){
                    cperror("malloc");
                    free(body);
                    continue;
                }
                body->size = rc;
                rc = push_tlv(body, dinfo->neighbour);
                if (rc < 0) {
                    cprint(STDERR_FILENO, "Could not insert go away into message queue\n");
                    free(body->content);
                    free(body);
                }

                inet_ntop(AF_INET6, &dinfo->neighbour->addr->sin6_addr,
                          ipstr, INET6_ADDRSTRLEN);
                cprint(0, "Remove (%s, %u) from neighbour list and add to potential neighbours.\n",
                    ipstr, ntohs(dinfo->neighbour->addr->sin6_port));
                cprint(0, "He did not answer to data for too long.\n");

                if (hashset_remove(neighbours,
                               dinfo->neighbour->addr->sin6_addr.s6_addr,
                               dinfo->neighbour->addr->sin6_port) == NULL){
                    cprint(STDERR_FILENO, "%s:%d Tried to remove a neighbour that wasn't one.\n",
                        __FILE__, __LINE__);
                }

                rc = hashset_add(potential_neighbours, dinfo->neighbour);
                if (rc == 0){
                    perrorbis(ENOMEM, "hashset_add");
                } else if (rc == 2){
                    cprint(STDERR_FILENO, "%s:%d Tried to add a potential neighbour that was already one.\n",
                        __FILE__, __LINE__);
                }

                if (!list_add(&to_delete, dinfo->neighbour))
                    cperror("list_add");
                continue;
            }

            if (now >= dinfo->time) {
                body = create_body();
                if (!body){
                    cperror("malloc");
                    continue;
                }

                body->content = voidndup(data, size);
                if (!body->content) {
                    free(body);
                    perrorbis(ENOMEM, "malloc");
                    continue;
                }

                body->size = size;
                rc = push_tlv(body, dinfo->neighbour);
                if (rc < 0) {
                    cprint(STDERR_FILENO, "%s:%d Could not insert data into message queue\n",
                        __FILE__, __LINE__);
                    free(body->content);
                    free(body);
                }

                continue;
            }

            delta = dinfo->time - now;

            if (delta < tv) {
                tv = delta;
            }
        }
    }


    neighbour_t *obj;
    u_int8_t buf[18];
    while ((obj = list_pop(&to_delete)) != NULL){
        inet_ntop(AF_INET6, &obj->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN);
        cprint(0, "Remove (%s, %u) from map.\n", ipstr, ntohs(obj->addr->sin6_port));

        bytes_from_neighbour(obj, buf);
        rc = hashmap_remove(map, buf, 1, 1);
        if (rc == 0)
            cprint(STDERR_FILENO, "%s:%d Tried to remove a dataid from flooding map but it wasn't in.\n",
                __FILE__, __LINE__);
    }

    if (map->size == 0 && !list_add(msg_done, voidndup(dataid, 12)))
        cperror("list_add");
    pthread_mutex_unlock(&map->mutex);

    return tv;
}

int message_flooding(struct timespec *tv) {
    size_t i;
    int rc;
    list_t *l, *msg_done = 0;
    char *dataid;
    hashmap_t *map;

    pthread_mutex_lock(&data_map->mutex);
    pthread_mutex_lock(&flooding_map->mutex);

    for (i = 0; i < flooding_map->capacity; i++) {
        for (l = flooding_map->tab[i]; l; l = l->next) {
            dataid = (char*)((map_elem*)l->val)->key;

            rc = flooding_send_msg(dataid, &msg_done);
            if (rc < 0)
                continue;

            if (rc < tv->tv_sec)
                tv->tv_sec = rc;
        }
    }

    while((dataid = list_pop(&msg_done)) != NULL) {
        map = hashmap_get(flooding_map, dataid);
        if (map){
            if (hashmap_remove(flooding_map, dataid, 1, 0) == 0)
                cprint(STDERR_FILENO, "%s:%d Tried to remove a dataid from flooding map but it wasn't in.\n",
                    __FILE__, __LINE__);
            hashmap_destroy(map, 1);
        }
        else
            cprint(STDERR_FILENO, "%s:%d Tried to get a dataid from flooding map but it wasn't in.\n",
                __FILE__, __LINE__);

        free(dataid);
    }

    pthread_mutex_unlock(&flooding_map->mutex);
    pthread_mutex_unlock(&data_map->mutex);

    return 0;
}
