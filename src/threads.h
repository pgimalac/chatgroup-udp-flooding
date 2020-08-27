#ifndef __H_THREADS
#define __H_THREADS

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define NUMBER_THREAD 4

pthread_t web_pt, rec_pt, send_pt, input_pt;
char web_running, rec_running, send_running, input_running;
pthread_cond_t cond_end_thread;
pthread_mutex_t mutex_end_thread;

pthread_t *thread_id[NUMBER_THREAD];
char *runnings[NUMBER_THREAD];
void *(*starters[NUMBER_THREAD])(void *);

int launch_threads();

void *web_thread(void *running);
void *rec_thread(void *running);
void *send_thread(void *running);
void *input_thread(void *running);

#endif
