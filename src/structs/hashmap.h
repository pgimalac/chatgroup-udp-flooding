#ifndef __H_HASHMAP
#define __H_HASHMAP

#include <pthread.h>

#include "list.h"

typedef struct hashmap {
    size_t size, capacity, keylen;
    list_t **tab;
    pthread_mutex_t mutex;
} hashmap_t;

typedef struct map_elem {
    void *key;
    void *value;
} map_elem;

/**
 * Allocate a new hashset
 */
hashmap_t* hashmap_init(int keylen);

/**
 * Add the given element in the given set
 * Change the value if the element already exists
 */
short hashmap_add(hashmap_t *map, const void *key, void *value);

/**
 * Return the value for a given key
 * return NULL if the key does not exists
 */
void *hashmap_get(hashmap_t *map, const void *key);

/**
 * Remove the given element of the set
 */
short hashmap_remove(hashmap_t *map, const void *key, short, short);

/**
 * return 1 if the given element is in the set, 0 otherwise
 */
short hashmap_contains(hashmap_t *map, const char *key);

/**
 * free all memory used by the map
 */
void hashmap_destroy(hashmap_t *map, short);

#endif
