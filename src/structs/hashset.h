#ifndef __H_HASHSET
#define __H_HASHSET

#include "list.h"
#include "types.h"

typedef struct hashset_t {
    int size, capacity;
    list_t** tab;
} hashset_t;

/**
 * Allocate a new hashset
 */
hashset_t* hashset_init();

/**
 * Returns if the hashset is empty
 */
short hashset_isempty(hashset_t*);

/**
 * Add the given element in the given set
 */
short hashset_add(hashset_t*, neighbour_t*);

/**
 * Remove the given element of the set
 */
short hashset_remove(hashset_t*, const u_int8_t[16], u_int16_t);

/**
 * return 1 if the given element is in the set, 0 otherwise
 */
short hashset_contains(hashset_t*, const u_int8_t[16], u_int16_t);

/**
 * returns the neighbour_t with the given ip and port, if there is none then NULL
 */
neighbour_t *hashset_get(hashset_t *h, const u_int8_t* ip, u_int16_t port);

/**
 * free all memory used by the set
 */
void hashset_destroy(hashset_t*);

/**
 * iterate though all the elements of the hashset
 */
void hashset_iter(hashset_t *h, void(*)(const neighbour_t*));

#endif
