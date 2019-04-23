#ifndef __H_UTILS
#define __H_UTILS

#include <stdlib.h>

#include "types.h"

#define logfd 2
#define FREE_BODY 1

/**
 * Generic usefull functions
 */

void* voidndup(const void*, int);

int init_random();

u_int64_t random_uint64();

u_int32_t random_uint32();

void free_message(message_t *msg, short free_body);

unsigned int hash_neighbour_data(const u_int8_t ip[16], u_int16_t port);

unsigned int hash_neighbour(const neighbour_t *n);

unsigned int hash(const char*);

unsigned int hash_msg_id(const char idnonce[12]);

#endif
