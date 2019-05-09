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

int clean_old_data() {
    size_t i;
    list_t *l, *to_delete = 0;
    datime_t *datime;

    pthread_mutex_lock(&data_map->mutex);

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

    pthread_mutex_unlock(&data_map->mutex);

    return i;
}

int clean_data_from_frags(frag_t *frag) {
    size_t i;
    list_t *l, *to_delete = 0;
    datime_t *datime;
    u_int8_t *key;

    pthread_mutex_lock(&data_map->mutex);

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

    pthread_mutex_unlock(&data_map->mutex);

    return i;
}

int clean_old_frags() {
    size_t i, count = 0;
    list_t *l, *to_delete = 0;
    frag_t *frag;
    time_t now = time(0);

    pthread_mutex_lock(&fragmentation_map->mutex);

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

    pthread_mutex_unlock(&fragmentation_map->mutex);

    return i;
}
