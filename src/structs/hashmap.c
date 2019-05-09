#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "interface.h"
#include "list.h"
#include "hashmap.h"
#include "utils.h"

#define HASHMAP_INITIAL_CAPACITY 128
#define HASHMAP_RATIO_UPPER_LIMIT 0.8
#define HASHMAP_RATIO_LOWER_LIMIT 0.1

static map_elem *elem(void *key, void *value) {
    map_elem *e = malloc(sizeof(map_elem));
    if (e) {
        e->key = key;
        e->value = value;
    }

    return e;
}

static short resize (hashmap_t *map, int capacity) {
    map_elem *e;
    list_t **tab = calloc(capacity, sizeof(list_t *));
    if (!tab) return 0;

    for (size_t i = 0; i < map->capacity; i++)
        for (list_t *l = map->tab[i]; l; ) {
            e = (map_elem*)list_pop(&l);
            if (!list_add(&tab[hash_key(e->key, map->keylen) % capacity], e)){
                free(tab);
                return 0;
            }
        }

    free(map->tab);
    map->capacity = capacity;
    map->tab = tab;
    return 1;
}

hashmap_t *hashmap_init(int keylen) {
    hashmap_t *map = malloc(sizeof(hashmap_t));
    if (map) {
        map->size = 0;
        map->capacity = HASHMAP_INITIAL_CAPACITY;
        map->keylen = keylen;

        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&map->mutex, &attr);
        pthread_mutexattr_destroy(&attr);

        map->tab = calloc(map->capacity, sizeof(list_t *));
        if(!map->tab) {
            free (map);
            map = NULL;
        }
    }

    return map;
}

static map_elem *get (hashmap_t *map, const void *key) {
    if (map == NULL) return NULL;

    map_elem *elem = NULL;
    pthread_mutex_lock(&map->mutex);

    map_elem *e;
    for (list_t *l = map->tab[hash_key(key, map->keylen) % map->capacity]; l; l = l->next) {
        e = (map_elem*)l->val;
        if (memcmp(e->key, key, map->keylen) == 0){
            elem = e;
            break;
        }
    }

    pthread_mutex_unlock(&map->mutex);

    return elem;
}

short hashmap_add(hashmap_t *map, const void *key, void *value) {
    if (map == 0) return 0;

    pthread_mutex_lock(&map->mutex);

    map_elem *e = get(map, key);
    if (e) {
        pthread_mutex_unlock(&map->mutex);
        return 2;
    }
    if (map->size + 1 > HASHMAP_RATIO_UPPER_LIMIT * map->capacity && !resize(map, map->capacity * 2)){
        pthread_mutex_unlock(&map->mutex);
        return -1;
    }

    void * newkey = voidndup(key, map->keylen);
    e = elem(newkey, value);
    if (e == NULL){
        free(newkey);
        pthread_mutex_unlock(&map->mutex);
        return 0;
    }

    if (!list_add(&map->tab[hash_key(key, map->keylen) % map->capacity], e)){
        free(newkey);
        pthread_mutex_unlock(&map->mutex);
        return 0;
    }
    map->size++;

    pthread_mutex_unlock(&map->mutex);

    return 1;
}

void *hashmap_get(hashmap_t *map, const void *key) {
    struct map_elem *e = get(map, key);
    return e ? e->value : NULL;
}

static short map_list_remove (list_t **lst, const void *key, size_t keylen, short k, short v) {
    if (lst == NULL || *lst == NULL)
        return 0;

    list_t* tmp;
    if (memcmp(key, ((map_elem*)(*lst)->val)->key, keylen) == 0) {
        tmp = (*lst);
        *lst = (*lst)->next;
    } else {
        while ((*lst)->next && memcmp(key, ((map_elem*)(*lst)->next->val)->key, keylen))
            lst = &(*lst)->next;

        if (!(*lst)->next)
            return 0;

        tmp = (*lst)->next;
        (*lst)->next = tmp->next;
    }

    if (k)
        free(((map_elem*)tmp->val)->key);
    if (v)
        free(((map_elem*)tmp->val)->value);


    free(tmp->val);
    free(tmp);
    return 1;
}

short hashmap_remove(hashmap_t *map, const void *key, short k, short v) {
    if (!map) return 0;

    short ret = 0;
    pthread_mutex_lock(&map->mutex);

    int hash = hash_key(key, map->keylen) % map->capacity;
    if(map_list_remove(&map->tab[hash], key, map->keylen, k, v)) {
        map->size--;

        ret = 1;
    }

    pthread_mutex_unlock(&map->mutex);
    return ret;
}

short hashmap_contains (hashmap_t *map, const char *key) {
    return get(map, key) != 0;
}

void hashmap_destroy(hashmap_t *map, short f) {
    if (map == 0) return;

    pthread_mutex_lock(&map->mutex);

    for (size_t i = 0; i < map->capacity; i++)
        for (list_t* l = map->tab[i]; l; free(list_pop(&l)))
            if (f){
                free(((map_elem*)l->val)->key);
                free(((map_elem*)l->val)->value);
            }
    free(map->tab);
    pthread_mutex_unlock(&map->mutex);
    pthread_mutex_destroy(&map->mutex);
    free(map);
}
