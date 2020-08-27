#ifndef __H_SIGNAL
#define __H_SIGNAL

#include <pthread.h>
#include <signal.h>

void quit(int rc);
void cleaner(void *running);

#endif
