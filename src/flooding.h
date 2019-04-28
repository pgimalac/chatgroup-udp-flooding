#ifndef __H_INNONDATION
#define __H_INNONDATION

#include "types.h"

#define MAX_NB_NEIGHBOUR 100

void send_data(char *buffer, int size);

void hello_potential_neighbours(struct timeval *tv);

int hello_neighbours(struct timeval *tv);

int flooding_add_message(const u_int8_t *data, int size);

int message_flooding(struct timeval *tv);

int clean_old_data();

void neighbour_flooding(short);

#endif
