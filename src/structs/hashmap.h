#ifndef __H_HASHMAP
#define __H_HASHMAP

#include "list.h"

typedef struct hashmap {
    int size, capacity, keylen;
    list_t **tab;
    unsigned int (*hash)(const void*);
} hashmap_t;

/**
 * Allocate a new hashset
 */
hashmap_t* hashmap_init(int keylen, unsigned int (*hash)(const void*));

/**
 * Add the given element in the given set
 * Change the value if the element already exists
 */
short hashmap_add(hashmap_t *map, void *key, void *value, short);

/**
 * Return the value for a given key
 * return NULL if the key does not exists
 */
void *hashmap_get(hashmap_t *map, void *key);

/**
 * Remove the given element of the set
 */
short hashmap_remove(hashmap_t *map, void *key, short);

/**
 * return 1 if the given element is in the set, 0 otherwise
 */
short hashmap_contains(hashmap_t *map, char *key);

/**
 * free all memory used by the map
 */
void hashmap_destroy(hashmap_t *map, short);

#endif
