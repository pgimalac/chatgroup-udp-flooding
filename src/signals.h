#ifndef __H_SIGNAL
#define __H_SIGNAL

#include <signal.h>
#include <pthread.h>

void quit(int rc);
void crit_err_hdlr(int sig_num, siginfo_t * info, void * ucontext);
void cleaner(void *running);

#endif
