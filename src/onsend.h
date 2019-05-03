#ifndef __H_ONSEND
#define __H_ONSEND

#include "types.h"

int send_message(int sock, message_t *msg, struct timespec *tv);

#endif
