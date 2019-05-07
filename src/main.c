#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <readline/readline.h>

#include "tlv.h"
#include "types.h"
#include "utils.h"
#include "network.h"
#include "interface.h"
#include "tlv.h"
#include "flooding.h"
#include "websocket.h"
#include "onsend.h"

#define MIN_PORT 1024
#define MAX_PORT 49151

static pthread_t web_pt, rec_pt, send_pt, input_pt;
static char web_running = 0, rec_running = 0, send_running = 0, input_running = 0;
static pthread_cond_t cond_end_thread;
static pthread_mutex_t mutex_end_thread;

static pthread_cond_t initiate_cond(){
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    return cond;
}

int init(){
    init_random();
    id = random_uint64();
    globalnum = 0;

    rl_catch_signals = 0;

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    // to avoid any deadlock

    pthread_mutex_init(&globalnum_mutex, &attr);
    pthread_mutex_init(&mutex_end_thread, &attr);
    cond_end_thread = initiate_cond();
    send_cond = initiate_cond();

    neighbours = hashset_init();
    if (neighbours == NULL){
        return -1;
    }

    potential_neighbours = hashset_init();
    if (potential_neighbours == NULL){
        hashset_destroy(neighbours);
        return -1;
    }

    httpport = (rand() % 10) + 8080;
    clientsockets = 0;
    webmessage_map = hashmap_init(sizeof(int));

    sprintf(tmpdir, "chat_%lx", random_uint64());
    char fptmpdir[1024];
    sprintf(fptmpdir, "/tmp/%s", tmpdir);
    int rc = mkdir(fptmpdir, 0722);
    if (rc < 0) {
        perror("mkdir");
        return -1;
    }

    cprint(0, "Create tmpdir %s.\n", fptmpdir);

    flooding_map = hashmap_init(12);
    if (flooding_map == NULL){
        hashset_destroy(neighbours);
        hashset_destroy(potential_neighbours);
        return -1;
    }

    data_map = hashmap_init(12);
    if (data_map == NULL){
        hashset_destroy(neighbours);
        hashset_destroy(potential_neighbours);
        hashmap_destroy(flooding_map, 0);
        return -1;
    }

    fragmentation_map = hashmap_init(12);
    if (fragmentation_map == NULL){
        hashset_destroy(neighbours);
        hashset_destroy(potential_neighbours);
        hashmap_destroy(flooding_map, 0);
        hashmap_destroy(data_map, 0);
        return -1;
    }

    pthread_mutex_init(&write_mutex, &attr);
    pthread_mutex_init(&queue_mutex, &attr);
    pthread_mutex_init(&clientsockets_mutex, &attr);

    pthread_mutexattr_destroy(&attr);

    return 0;
}

void init_arguments(int argc, char **argv, u_int16_t *port){
    if (argc >= 1){
        char *pos = 0;
        long int port2 = strtol(argv[0], &pos, 0);
        if (*pos == '\0' && port2 >= MIN_PORT && port2 <= MAX_PORT)
            *port = (unsigned short)port2;
    }

    logfd = 2;
    if (argc >= 2){
        if (strcmp("1", argv[1]) == 0 ||
                strcasecmp("STDOUT", argv[1]) == 0)
            logfd = 1;
        else if (strcmp("2", argv[1]) == 0 ||
                strcasecmp("STDERR", argv[1]) == 0)
            logfd = 2;
        else {
            int fd = open(argv[1], O_WRONLY | O_CREAT);
            if (fd >= 0)
                logfd = fd;
            else
                cperror("open");
        }
    }

    if (argc >= 3)
        setPseudo(argv[2], strlen(argv[2]));
    else
        setRandomPseudo();
}


void cleaner(void *running){
    pthread_mutex_unlock(&write_mutex);
    pthread_mutex_unlock(&mutex_end_thread);
    pthread_mutex_unlock(&neighbours_mutex);
    pthread_mutex_unlock(&potential_neighbours_mutex);
    pthread_mutex_unlock(&flooding_map_mutex);
    pthread_mutex_unlock(&data_map_mutex);
    pthread_mutex_unlock(&fragmentation_map_mutex);
    pthread_mutex_unlock(&queue_mutex);
    pthread_mutex_unlock(&clientsockets_mutex);
    cprint(0, "CLEANER running.\n");

    pthread_mutex_lock(&mutex_end_thread);
    *(char*)running = 0;
    pthread_mutex_unlock(&mutex_end_thread);
    pthread_cond_broadcast(&cond_end_thread);
    cprint(0, "CLEANER ended\n");
}


void *web_thread(void *running){
    *(char*)running = 1;
    pthread_cleanup_push(cleaner, running);
    pthread_setcanceltype(PTHREAD_CANCEL_ENABLE, 0);
    list_t *to_delete = 0, *l;
    void *val;
    int rc, s;
    fd_set readfds;

    while (1){
        FD_ZERO(&readfds);
        FD_SET(websock, &readfds);
        int highest = websock;

        pthread_mutex_lock(&clientsockets_mutex);
        for (l = clientsockets; l; l = l->next) {
            s = *((int*)l->val);
            FD_SET(s, &readfds);
            highest = max(highest, s);
        }
        pthread_mutex_unlock(&clientsockets_mutex);

        rc = select(highest + 1, &readfds, 0, 0, NULL);
        if (rc < 0) {
            cperror("select");
            continue;
        }

        if (rc == 0)
            continue;

        pthread_mutex_lock(&clientsockets_mutex);
        if (FD_ISSET(websock, &readfds))
            handle_http();

        for (l = clientsockets; l; l = l->next) {
            s = *((int*)l->val);
            if (FD_ISSET(s, &readfds)) {
                rc = handle_ws(s);
                if (rc < 0)
                    list_add(&to_delete, l->val);
            }
        }

        while (to_delete) {
            val = list_pop(&to_delete);
            list_eremove(&clientsockets, val);
        }
        pthread_mutex_unlock(&clientsockets_mutex);
    }
    pthread_cleanup_pop(1);
}

void *rec_thread(void *running){
    *(char*)running = 1;
    pthread_cleanup_push(cleaner, running);
    pthread_setcanceltype(PTHREAD_CANCEL_ENABLE, 0);
    fd_set readfds;
    int rc;
    size_t i, number_recv = 1;

    while (1){
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        fprintf(stderr, "REC THREAD: before select.\n");
        rc = select(sock + 1, &readfds, 0, 0, 0);
        fprintf(stderr, "REC THREAD: after select.\n");

        if (rc < 0) {
            cperror("select");
            continue;
        }

        if (rc == 0)
            continue;

        if (FD_ISSET(sock, &readfds)) {
            fprintf(stderr, "REC THREAD: start reception loop.\n");
            for (i = 0; i < number_recv; i++)
                if (handle_reception() == -1){
                    if (number_recv > neighbours->size + 1)
                        number_recv--;
                    break;
                }

            fprintf(stderr, "REC THREAD: end reception loop.\n");
            if (i == number_recv && number_recv < 2 * neighbours->size)
                number_recv++;
        }
    }

    pthread_cleanup_pop(1);
}

void *send_thread(void *running){
    *(char*)running = 1;
    pthread_cleanup_push(cleaner, running);
    pthread_setcanceltype(PTHREAD_CANCEL_ENABLE, 0);
    int size;
    message_t *msg;
    struct timespec tv = { 0 };
    pthread_mutex_t useless = PTHREAD_MUTEX_INITIALIZER;

//    time_t start;
    while (1) {
        tv.tv_sec = MAX_TIMEOUT;

        //fprintf(stderr, "SEND THREAD: before hello neighbours.\n");
        size = hello_neighbours(&tv);
        //fprintf(stderr, "SEND THREAD: after hello neighbours.\n");
        if (size < MAX_NB_NEIGHBOUR){
            //fprintf(stderr, "SEND THREAD: before hello pot. neighbours.\n");
            hello_potential_neighbours(&tv);
            //fprintf(stderr, "SEND THREAD: after hello pot. neighbours.\n");
        }

        //fprintf(stderr, "SEND THREAD: before message flooding.\n");
        message_flooding(&tv);
        //fprintf(stderr, "SEND THREAD: before neighbour flooding.\n");
        neighbour_flooding(0);
        //fprintf(stderr, "SEND THREAD: after flooding.\n");

        //fprintf(stderr, "SEND THREAD: before pull loop.\n");
        while((msg = pull_message())) {
            //fprintf(stderr, "SEND THREAD: before send message.\n");
            send_message(sock, msg, &tv);
            //fprintf(stderr, "SEND THREAD: after send message.\n");
            free_message(msg);
        }
        //fprintf(stderr, "SEND THREAD: end pull loop.\n");

        clean_old_data();
        //fprintf(stderr, "SEND THREAD: after clean data.\n");
        clean_old_frags();
        //fprintf(stderr, "SEND THREAD: after clean frags.\n");

        pthread_mutex_lock(&useless);
        pthread_cond_timedwait(&send_cond, &useless, &tv);
        pthread_mutex_unlock(&useless);
    }

    pthread_cleanup_pop(1);
}

#define BUFFER_INPUT_SIZE 4096
void *input_thread(void *running){
    *(char*)running = 1;
    pthread_cleanup_push(cleaner, running);
    pthread_setcanceltype(PTHREAD_CANCEL_ENABLE, 0);

    while (1){
        fprintf(stderr, "INPUT THREAD: before readline.\n");
        char *line = readline("");
        fprintf(stderr, "INPUT THREAD: after readline.\n");

        if (line == NULL){ // end of stdin reached
            int *ret = malloc(sizeof(int));
            *ret = 0;
            pthread_exit(ret);
        }

        size_t len = strlen(line);
        char *buffer = purify(line, &len);
        fprintf(stderr, "INPUT THREAD: after purify.\n");

        #define S "\e1M\e[1A\e[K"

        if (len > 0) {
            fprintf(stderr, "INPUT THREAD: before input handle.\n");
            cprint(STDOUT_FILENO, S, strlen(S));
            print_message((u_int8_t*)buffer, len);
            handle_input(buffer, len);
            cprint(STDOUT_FILENO, CLBEG, strlen(CLBEG));
            fprintf(stderr, "INPUT THREAD: after input handle.\n");
        }
        free(line);
    }

    pthread_cleanup_pop(1);
}

#define NUMBER_THREAD 4

void quit(int rc){
    cprint(0, "quit\n");
    void *ret = NULL;

    pthread_t *thread_id[NUMBER_THREAD] = {&web_pt, &rec_pt, &send_pt, &input_pt};
    char *runnings[NUMBER_THREAD] = {&web_running, &rec_running, &send_running, &input_running};

    for (int i = 0; i < NUMBER_THREAD; i++)
        if (runnings[i]){
            cprint(0, "cancelling %d\n", i + 1);
            pthread_cancel(*thread_id[i]);
        }

    for (int i = 0; i < NUMBER_THREAD; i++){
        cprint(0, "joining %d\n", i + 1);
        pthread_join(*thread_id[i], &ret);
        if (ret != PTHREAD_CANCELED)
            free(ret);
    }

    quit_handler(rc);
}

int main(int argc, char **argv) {
    int rc;

    rc = init();
    if (rc != 0) return rc;
    cprint(0, "local id: %lx\n", id);

    unsigned short port = 0;
    init_arguments(argc - 1, argv + 1, &port);

    cprint(STDOUT_FILENO, "Welcome %s.\n", getPseudo());

    sock = start_server(port);
    if (sock < 0) {
        cprint(STDERR_FILENO, "coudn't create socket\n");
        return 1;
    }

    websock = create_tcpserver(httpport);
    if (websock < 0) {
        cprint(STDERR_FILENO, "Error while creating web server.\n");
        return 1;
    }

    cprint(STDOUT_FILENO, "Web interface on http://localhost:%d.\n", httpport);

    signal(SIGINT, quit);
    cprint(STDOUT_FILENO, "%s\n", SEPARATOR);

    void *ret = NULL;

    pthread_t *thread_id[NUMBER_THREAD] = {&web_pt, &rec_pt, &send_pt, &input_pt};
    char *runnings[NUMBER_THREAD] = {&web_running, &rec_running, &send_running, &input_running};
    void *(*starters[NUMBER_THREAD])(void*) = {web_thread, rec_thread, send_thread, input_thread};

    for (int i = 0; i < NUMBER_THREAD; i++){
        rc = pthread_create(thread_id[i], 0, starters[i], runnings[i]);
        if (rc != 0){
            cperror("Could not create initial threads.\n");
            rc = 1;
            goto quit;
        }
    }

    while (1) {
        pthread_mutex_lock(&mutex_end_thread);
        pthread_cond_wait(&cond_end_thread, &mutex_end_thread);

        for (int i = 0; i < NUMBER_THREAD; i++)
            if (*runnings[i] == 0){
                cprint(0, "THREAD %d ended\n", i + 1);
                pthread_join(*thread_id[i], &ret);
                cprint(0, "The thread was joined.\n");

                if (ret == PTHREAD_CANCELED || ret == NULL){
                    // cancel thread so there is a thread running 'quit'
                    cprint(0, "Thread %d was cancelled.\n", i);
                    pthread_mutex_unlock(&mutex_end_thread);
                    sleep(3);
                    return 1;
                }

                if (*(int*)ret == 0){ // normal shutdown
                    free(ret);
                    rc = 0;
                    goto quit;
                }
                free(ret);

                cprint(STDERR_FILENO, "A thread was stopped, trying to restart it\n");
                rc = pthread_create(thread_id[i], NULL, starters[i], runnings[i]);
                if (rc){
                    sleep(5);
                    rc = pthread_create(thread_id[i], NULL, starters[i], runnings[i]);
                    if (rc){
                        cprint(STDERR_FILENO, "Could not restart the thread.\n");
                        rc = 1;
                        goto quit;
                    }
                }
                cprint(0, "Thread successfully restarted\n");
            }

        pthread_mutex_unlock(&mutex_end_thread);
    }

    quit:
        pthread_mutex_unlock(&mutex_end_thread);
        quit(rc);
}
