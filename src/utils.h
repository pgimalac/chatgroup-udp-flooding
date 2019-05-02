#ifndef __H_UTILS
#define __H_UTILS

#include <stdlib.h>
#include <stdarg.h>

#include "types.h"

int logfd;
char tmpdir[255];

/**
 * Generic usefull functions
 */

pid_t httppid;

void* voidndup(const void*, int);

void init_random();

u_int64_t random_uint64();

u_int32_t random_uint32();

void free_message(message_t *msg);

unsigned int hash_neighbour_data(const u_int8_t ip[16], u_int16_t port);

unsigned int hash_key(const char *idnonce, int len);

char *strappl(char* str1, ...);

char *strappv(char** str);

void bytes_from_neighbour(const neighbour_t *n, u_int8_t buffer[18]);

void print_bytes(const unsigned char *buf, size_t len);

void perrorbis(int err, const char *str);

void cperror(const char *str);

void cprint(int fd, char *str, ...);

int min(int, int);

int max(int a, int b);

char *purify(char *buffer, size_t *len);

#endif
