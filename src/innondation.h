#ifndef __H_INNONDATION
#define __H_INNONDATION

#include "types.h"

void send_data(const char *buffer, int size);

void hello_potential_neighbours();

int hello_neighbours(struct timeval *tv);

int innondation_add_message(const char *data, int size);

int innondation_send_msg(const char *dataid);

int message_innondation(struct timeval *tv);

#endif
