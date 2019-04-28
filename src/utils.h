#ifndef __H_UTILS
#define __H_UTILS

#include <stdlib.h>
#include <stdarg.h>

#include "types.h"

#define logfd 1

/**
 * Generic usefull functions
 */

void* voidndup(const void*, int);

int init_random();

u_int64_t random_uint64();

u_int32_t random_uint32();

void free_message(message_t *msg);

unsigned int hash_neighbour_data(const u_int8_t ip[16], u_int16_t port);

unsigned int hash_key(const char *idnonce, int len);

char *strappl(char* str1, ...);

char *strappv(char** str);

void bytes_from_neighbour(const neighbour_t *n, u_int8_t buffer[18]);

void print_bytes(const char *buf, size_t len);

void perrorbis(int fd, int, char *str, char *B, char *F);

#endif
