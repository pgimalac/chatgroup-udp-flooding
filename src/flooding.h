#ifndef __H_INNONDATION
#define __H_INNONDATION

#include "types.h"

#define MAX_NB_NEIGHBOUR 100

u_int32_t nonce;

void send_data(u_int8_t type, const char *buffer, u_int16_t size);

void hello_potential_neighbours(struct timeval *tv);

int hello_neighbours(struct timeval *tv);

int flooding_add_message(const u_int8_t *data, int size);

int message_flooding(struct timeval *tv);

int clean_old_data();

int clean_old_frags();

void neighbour_flooding(short);

#endif
