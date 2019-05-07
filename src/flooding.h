#ifndef __H_INNONDATION
#define __H_INNONDATION

#include "types.h"

#define MAX_TIMEOUT 30

#define MAX_NB_NEIGHBOUR 100

u_int32_t globalnum;
pthread_mutex_t globalnum_mutex;

body_t *create_body();

void send_data(u_int8_t type, const char *buffer, u_int16_t size);

void hello_potential_neighbours(struct timespec *tv);

int hello_neighbours(struct timespec *tv);

int flooding_add_message(const u_int8_t *data, int size, int user);

int message_flooding(struct timespec *tv);

int clean_old_data();

int clean_old_frags();

void neighbour_flooding(short);

#endif
