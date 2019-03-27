#ifndef __H_UTILS
#define __H_UTILS

#include <stdlib.h>

#include "types.h"

#define FREE_BODY 1

/**
 * Generic usefull functions
 */

int init_random();

u_int64_t random_uint64();

u_int32_t random_uint32();

void free_message(message_t *msg, short free_body);

#endif
