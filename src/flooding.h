#ifndef __H_INNONDATION
#define __H_INNONDATION

#include "types.h"

void send_data(char *buffer, int size);

void hello_potential_neighbours(struct timeval *tv);

int hello_neighbours(struct timeval *tv);

int flooding_add_message(const char *data, int size);

int message_flooding(struct timeval *tv);

void neighbour_flooding(short);

#endif
