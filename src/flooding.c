#include <stdio.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
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

#define MAX_TIMEOUT 30

// number of shot hello before removing from potential neighbour
#define NBSH 5

#define SYM_TIMEOUT 120

#define NEIGHBOUR_TIMEOUT 120

#define CLEAN_TIMEOUT 45

#define FRAG_TIMEOUT 60

void frag_data(u_int8_t type, const char *buffer, u_int16_t size) {
    uint16_t i = 0, n = size / 233, count = 0, len;
    uint16_t nsize = htons(size), pos;
    body_t data = { 0 };
    char content[256], *offset;
    u_int32_t nonce_frag = random_uint32();

    cprint(0, "Fragment message of total size %u bytes.\n", size);

    for (i = 0; i <= n; i++) {
        offset = content;
        memset(offset, 0, 256);
        memcpy(offset, &nonce_frag, sizeof(nonce_frag));
        offset += sizeof(nonce_frag);

        *offset++ = type; // data type

        memcpy(offset, &nsize, 2); // size
        offset += 2;

        pos = htons(count);
        memcpy(offset, &pos, 2); // position
        offset += 2;

        len = size - count < 233 ? size - count : 233;
        memcpy(offset, buffer + count, len);
        offset += len;

        data.size = tlv_data(&data.content, id, random_uint32(), 220, content, len + 9);
        flooding_add_message(data.content, data.size);
        free(data.content);
        count += len;
    }
}

void send_data(u_int8_t type, const char *buffer, u_int16_t size){
    if (buffer == 0 || size <= 0) return;

    if (size > 255) {
        frag_data(type, buffer, size);
        return;
    }

    body_t data = { 0 };
    int rc = tlv_data(&data.content, id, random_uint32(), type, buffer, size);

    if (rc < 0){
        if (rc == -1)
            cperror("tlv_data");
        else if (rc == -2)
            cprint(0, "Message too long but supposed to be cut...\n");
        return;
    }

    data.size = rc;

    if (flooding_add_message(data.content, data.size) != 0)
        cperror("tlv_data");

    free(data.content);
}

void hello_potential_neighbours(struct timeval *tv) {
    int rc;
    size_t i;
    time_t max, delta, now = time(0);
    assert(now != -1);
    list_t *l;
    neighbour_t *p;
    body_t *hello;
    char ipstr[INET6_ADDRSTRLEN];

    list_t *to_delete = NULL;

    for (i = 0; i < potential_neighbours->capacity; i++) {
        for (l = potential_neighbours->tab[i]; l != NULL; l = l->next) {
            p = (neighbour_t*)l->val;

            if (p->short_hello_count >= NBSH) {
                assert (inet_ntop(AF_INET6, &p->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
                cprint(0, "Remove (%s, %u) from potential neighbour list.\n",
                       ipstr, ntohs(p->addr->sin6_port));
                cprint(0, "He did not answer to short hello for too long.\n");

                if (list_add(&to_delete, p) == 0){
                    cperror("list_add");
                }
                continue;
            }

            delta = now - p->last_hello_send;
            max = 1 << (p->short_hello_count + 4);

            if (delta >= max) {
                hello = malloc(sizeof(body_t));
                if (hello == NULL){
                    cperror("malloc");
                    continue;
                }

                rc = tlv_hello_short(&hello->content, id);
                if (rc < 0){
                    cperror("tlv_hello_short");
                    free(hello);
                    continue;
                }
                hello->size = rc;

                rc = push_tlv(hello, p);
                if (rc < 0) {
                    cprint(STDERR_FILENO, "Could not insert short hello into message queue\n");
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

        if (n->tutor_id) {
            neighbour_t *m = hashset_get(neighbours, n->tutor_id, *(u_int16_t*)(n->tutor_id + 16));
            char msg[256] = { 0 };
            if (m) {
                hello = malloc(sizeof(body_t));
                if (hello){
                    assert (inet_ntop(AF_INET6, n->addr->sin6_addr.s6_addr,
                                  ipstr, INET6_ADDRSTRLEN) != NULL);

                    sprintf(msg, "You recommended (%s, %u) but I can't reach it.",
                            ipstr, ntohs(*(u_int16_t*)(n->tutor_id + 16)));
                    cprint(0, "%s\n", msg);

                    hello->size = tlv_warning(&hello->content, msg, strlen(msg));
                    push_tlv(hello, m);
                } else
                    cperror("malloc");
            }
        }

        if (!hashset_remove_neighbour(potential_neighbours, n))
            cprint(STDERR_FILENO, "%s:%d Tried to remove a potential neighbour but it wasn't in the potential neighbour set.\n");
        free(n->addr);
        free(n->tutor_id);
        free(n);
    }
}

int hello_neighbours(struct timeval *tv) {
    neighbour_t *p;
    int rc;
    size_t i, size = 0;
    time_t now = time(0), delta;
    assert(now != -1);

    list_t *l, *to_delete = 0;
    char ipstr[INET6_ADDRSTRLEN];
    tv->tv_sec = MAX_TIMEOUT;
    tv->tv_usec = 0;

    for (i = 0; i < neighbours->capacity; i++) {
        for (l = neighbours->tab[i]; l; l = l->next, size++) {
            p = (neighbour_t*)l->val;
            if (now - p->last_hello < SYM_TIMEOUT) {
                delta = now - p->last_hello_send;
                if (delta >= MAX_TIMEOUT) {
                    body_t *hello = malloc(sizeof(body_t));
                    if (hello == NULL){
                        cperror("malloc");
                        continue;
                    }

                    rc = tlv_hello_long(&hello->content, id, p->id);
                    if (rc < 0){
                        cperror("tlv_hello_long");
                        free(hello);
                        continue;
                    }
                    hello->size = rc;

                    rc = push_tlv(hello, p);
                    if (rc < 0) {
                        cprint(STDERR_FILENO, "Could not insert long hello into message queue\n");
                        free(hello->content);
                        free(hello);
                    }
                } else if (MAX_TIMEOUT - delta < tv->tv_sec) {
                    tv->tv_sec = MAX_TIMEOUT - delta;
                }
            } else if (list_add(&to_delete, p) == 0){
                cperror("list_add");
            }
        }
    }

    while (to_delete) {
        p = (neighbour_t*)list_pop(&to_delete);
        if (!hashset_remove(neighbours, p->addr->sin6_addr.s6_addr, p->addr->sin6_port))
            cprint(STDERR_FILENO, "%s:%d Tried to remove a neighbour that wasn't actually one.\n",
                __FILE__, __LINE__);
        rc = hashset_add(potential_neighbours, p);
        if (rc == 2)
            cprint(STDERR_FILENO, "%s:%d Tried to add to potentials a neighbour that was already in.\n",
                __FILE__, __LINE__);
        else if (rc == 0){
            perrorbis(ENOMEM, "hashset_add");
            free(p->addr);
            free(p->tutor_id);
            free(p);
            return -1;
        }

        assert (inet_ntop(AF_INET6, &p->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
        cprint(0, "Remove (%s, %u) from neighbour list and add to potential neighbours.\n",
            ipstr, ntohs(p->addr->sin6_port));
        cprint(0, "He did not send long hello for too long \n");
    }

    return size;
}

int flooding_add_message(const u_int8_t *data, int size) {
    neighbour_t *p;
    data_info_t *dinfo;
    datime_t *datime;
    time_t now = time(0);
    assert(now != -1);
    int rc;

    size_t i;
    list_t *l;
    u_int8_t buffer[18], key[12];

    hashmap_t *ns = hashmap_init(18);
    if (!ns) {
        perrorbis(ENOMEM, "hashmap_init");
        return -1;
    }

    for (i = 0; i < neighbours->capacity; i++) {
        for (l = neighbours->tab[i]; l; l = l->next) {
            p = (neighbour_t*)l->val;

            dinfo = malloc(sizeof(data_info_t));
            if (!dinfo) {
                cperror("malloc");
                continue;
            }
            memset(dinfo, 0, sizeof(data_info_t));

            dinfo->neighbour = p;
            dinfo->time = now + rand() % 2;
            dinfo->pmtu_discover = 0;

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

    memcpy(key, data + 2, 12);

    datime = malloc(sizeof(datime_t));
    datime->data = voidndup(data, size);
    datime->last = now;

    rc = hashmap_add(flooding_map, key, ns);
    if (rc == 2)
        cprint(STDERR_FILENO, "%s:%d Tried to add a map in the flooding_map but it was already in.\n",
            __FILE__, __LINE__);
    else if (rc == 0)
        perrorbis(ENOMEM, "hashmap_add");
    if (rc != 1)
        hashmap_destroy(ns, 1);

    rc = hashmap_add(data_map, key, datime);
    if (rc == 2)
        cprint(STDERR_FILENO, "%s:%d Tried to add a data in data_map but it was already in.\n",
            __FILE__, __LINE__);
    else if (rc == 0)
        perrorbis(ENOMEM, "hashset_add");

    return 0;
}

int flooding_send_msg(const char *dataid, list_t **msg_done) {
    size_t i, size;
    int rc;
    time_t tv = MAX_TIMEOUT, delta, now = time(0);
    assert(now != -1);

    list_t *l, *to_delete = 0;
    data_info_t *dinfo;
    datime_t *datime;
    body_t *body;
    char ipstr[INET6_ADDRSTRLEN];
    u_int8_t *data;
    hashmap_t *map;

    datime = hashmap_get(data_map, dataid);
    if (!datime) {
        cprint(STDERR_FILENO, "%s:%d Data_map did not contained a dataid it was supposed to contain.\n",
            __FILE__, __LINE__);
        return -1;
    }

    datime->last = now;
    data = datime->data;
    size = data[1] + 2;

    map = hashmap_get(flooding_map, dataid);
    if (!map){
        cprint(STDERR_FILENO, "%s:%d Flooding_map did not contained a dataid it was supposed to contain.\n",
            __FILE__, __LINE__);
        return -2;
    }

    for (i = 0; i < map->capacity; i++) {
        for (l = map->tab[i]; l; l = l->next) {
            dinfo = (data_info_t*)((map_elem*)l->val)->value;

            if (!hashset_get(neighbours,
                            dinfo->neighbour->addr->sin6_addr.s6_addr,
                            dinfo->neighbour->addr->sin6_port)) {
                list_add(&to_delete, dinfo->neighbour);
                continue;
            }

            if (now >= dinfo->time && dinfo->send_count >= 5) {
                body = malloc(sizeof(body_t));
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

                assert (inet_ntop(AF_INET6, &dinfo->neighbour->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
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

                if (!list_add(&to_delete, dinfo->neighbour)){
                    cperror("list_add");
                }
                continue;
            }

            if (now >= dinfo->time) {
                body = malloc(sizeof(body_t));
                if (!body){
                    cperror("malloc");
                    continue;
                }

                body->content = voidndup(data, size);
                if (!body->content) {
                    free(body);
                    cperror("malloc");
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

                dinfo->pmtu_discover = rc;

                continue;
            }

            delta = dinfo->time - now;

            if (delta < tv) {
                tv = delta;
            }
        }
    }

    neighbour_t *obj;
    while ((obj = list_pop(&to_delete)) != NULL){
        assert (inet_ntop(AF_INET6, &obj->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
        cprint(0, "Remove (%s, %u) from map.\n", ipstr, ntohs(obj->addr->sin6_port));

        u_int8_t buf[18];
        bytes_from_neighbour(obj, buf);
        rc = hashmap_remove(map, buf, 1, 1);
        if (rc == 0)
            cprint(STDERR_FILENO, "%s:%d Tried to remove a dataid from flooding map but it wasn't in.\n",
                __FILE__, __LINE__);
    }

    if (map->size == 0 && !list_add(msg_done, voidndup(dataid, 12)))
        cperror("list_add");

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

    return 0;
}

int clean_old_data() {
    size_t i;
    list_t *l, *to_delete = 0;
    datime_t *datime;

    for (i = 0; i < data_map->capacity; i++) {
        for (l = data_map->tab[i]; l; l = l->next) {
            datime = ((map_elem*)l->val)->value;

            // never remove messages fragments
            // without removing all associated fragments
            if (datime->data[0] == 4 && datime->data[14] == DATA_FRAG)
                continue;

            if (time(0) - datime->last > CLEAN_TIMEOUT)
                list_add(&to_delete, datime);
        }
    }

    for (i = 0; to_delete; i++) {
        datime = list_pop(&to_delete);
        if (!hashmap_remove(data_map, datime->data + 2, 1, 0)){
            cprint(STDERR_FILENO, "%s:%d HASHMAP REMOVE COULD NOT REMOVE datime\n",
                __FILE__, __LINE__);
        }

        free(datime->data);
        free(datime);
    }

    if (i)
        cprint(0, "%lu old data removed.\n", i);

    return i;
}

int clean_data_from_frags(frag_t *frag) {
    size_t i;
    list_t *l, *to_delete = 0;
    datime_t *datime;
    u_int8_t *key;

    for (i = 0; i < data_map->capacity; i++) {
        for (l = data_map->tab[i]; l; l = l->next) {
            datime = ((map_elem*)l->val)->value;
            key = ((map_elem*)l->val)->key;

            // here we consider only data
            if (datime->data[0] != 4 || datime->data[14] != DATA_FRAG)
                continue;

            // not the right sender_id
            if (memcmp(frag->id, key, 8))
                continue;

            // not right fragment nonce
            if (memcmp(frag->id + 8, datime->data + 15, 4))
                continue;

            list_add(&to_delete, datime);
        }
    }

    for (i = 0; to_delete; i++) {
        datime = list_pop(&to_delete);
        if (!hashmap_remove(data_map, datime->data + 2, 1, 0))
            cprint(STDERR_FILENO, "%s:%d HASHMAP REMOVE COULD NOT REMOVE datime\n", __FILE__, __LINE__);

        free(datime->data);
        free(datime);
    }

    return i;
}

int clean_old_frags() {
    size_t i, count = 0;
    list_t *l, *to_delete = 0;
    frag_t *frag;
    time_t now = time(0);

    for (i = 0; i < fragmentation_map->capacity; i++) {
        for (l = fragmentation_map->tab[i]; l; l = l->next) {
            count++;
            frag = ((map_elem*)l->val)->value;
            if (now - frag->last > FRAG_TIMEOUT) {
                list_add(&to_delete, frag);
            }
        }
    }

    i = 0;
    while (to_delete) {
        frag = list_pop(&to_delete);
        i += clean_data_from_frags(frag);
        hashmap_remove(fragmentation_map, frag->id, 1, 0);
        free(frag->id);
        free(frag->buffer);
        free(frag);
    }

    if (i)
        cprint(0, "%lu old message fragments removed.\n", i);

    return i;
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
                cperror("malloc");
                continue;
            }

            rc = tlv_neighbour(&body->content,
                                      &a->addr->sin6_addr,
                                      a->addr->sin6_port);
            if (rc < 0){
                free(body);
                cperror("malloc");
                continue;
            }
            body->size = rc;

            rc = push_tlv(body, p);
            if (rc < 0) {
                cprint(STDERR_FILENO, "%s:%d Could not insert data into message queue\n", __FILE__, __LINE__);
                free(body->content);
                free(body);
            }
        }
    }

    assert (inet_ntop(AF_INET6, &p->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
    cprint(0, "Send neighbours to (%s, %u).\n", ipstr, ntohs(p->addr->sin6_port));

    return 0;
}

void neighbour_flooding(short force) {
    size_t i;
    time_t now = time(0);
    assert(now != -1);

    list_t *l;
    neighbour_t *p;

    for (i = 0; i < neighbours->capacity; i++) {
        for (l = neighbours->tab[i]; l; l = l->next) {
            p = (neighbour_t*)l->val;
            if (force || now - p->last_neighbour_send > NEIGHBOUR_TIMEOUT) {
                send_neighbour_to(p);
            }
        }
    }
}
