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
 * Add the given element in the given set
 */
short hashset_add(hashset_t*, neighbour_t*);

/**
 * Remove the given element of the set
 */
short hashset_remove(hashset_t*, u_int8_t*, u_int16_t);

/**
 * return 1 if the given element is in the set, 0 otherwise
 */
short hashset_contains(hashset_t*, u_int8_t*, u_int16_t);

/**
 * free all memory used by the set
 */
void hashset_destroy(hashset_t*);

#endif
