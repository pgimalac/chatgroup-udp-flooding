#ifndef __H_SIGNAL
#define __H_SIGNAL

#include <signal.h>
#include <pthread.h>

void quit(int rc);
void cleaner(void *running);

#endif
