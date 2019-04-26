#ifndef __H_UTILS
#define __H_UTILS

#include <stdlib.h>
#include <stdarg.h>

#include "types.h"

#define logfd 2

/**
 * Generic usefull functions
 */

void* voidndup(const void*, int);

int init_random();

u_int64_t random_uint64();

u_int32_t random_uint32();

void free_message(message_t *msg);

unsigned int hash_neighbour_data(const u_int8_t ip[16], u_int16_t port);

unsigned int hash_neighbour(const char*);

unsigned int hash_msg_id(const char idnonce[12]);

char* strappl(char* str1, ...);

char* strappv(char** str);

#endif
