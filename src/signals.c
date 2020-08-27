#include "signals.h"
#include "flooding.h"
#include "network.h"
#include "threads.h"
#include "utils.h"
#include "websocket.h"

void cleaner(void *running) {
    pthread_mutex_unlock(&write_mutex);
    pthread_mutex_unlock(&mutex_end_thread);
    pthread_mutex_unlock(&neighbours_mutex);
    pthread_mutex_unlock(&potential_neighbours_mutex);
    pthread_mutex_unlock(&queue_mutex);
    pthread_mutex_unlock(&clientsockets_mutex);
    cprint(0, "CLEANER running.\n");

    pthread_mutex_lock(&mutex_end_thread);
    *(char *)running = 0;
    pthread_mutex_unlock(&mutex_end_thread);
    pthread_cond_broadcast(&cond_end_thread);
    cprint(0, "CLEANER ended\n");
}

void quit(int rc) {
    cprint(0, "quit\n");
    void *ret = NULL;

    pthread_t *thread_id[NUMBER_THREAD] = {&web_pt, &rec_pt, &send_pt,
                                           &input_pt};
    char *runnings[NUMBER_THREAD] = {&web_running, &rec_running, &send_running,
                                     &input_running};

    for (int i = 0; i < NUMBER_THREAD; i++)
        if (runnings[i]) {
            cprint(0, "cancelling %d\n", i + 1);
            pthread_cancel(*thread_id[i]);
        }

    for (int i = 0; i < NUMBER_THREAD; i++) {
        cprint(0, "joining %d\n", i + 1);
        pthread_join(*thread_id[i], &ret);
        if (ret != PTHREAD_CANCELED)
            free(ret);
    }

    quit_handler(rc);
}
