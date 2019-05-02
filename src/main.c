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

#include "tlv.h"
#include "types.h"
#include "utils.h"
#include "network.h"
#include "interface.h"
#include "tlv.h"
#include "flooding.h"
#include "websocket.h"

#define MIN_PORT 1024
#define MAX_PORT 49151

static pthread_t web_pt, rec_pt, send_pt, input_pt;
static char web_running = 0, rec_running = 0, send_running = 0, input_running = 0;
static pthread_cond_t cond_end_thread = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t mutex_end_thread = PTHREAD_MUTEX_INITIALIZER;


int init() {
    init_random();

    id = random_uint64();
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
    // unlock all mutexes, TODO

    pthread_mutex_lock(&mutex_end_thread);
    *(char*)running = 0;
    pthread_mutex_unlock(&mutex_end_thread);
    pthread_cond_broadcast(&cond_end_thread);
}



void *web_thread(void *_){
    web_running = 1;
    pthread_cleanup_push(cleaner, &web_running);
    pthread_setcanceltype(PTHREAD_CANCEL_ENABLE, 0);
    list_t *to_delete = 0, *l;
    void *val;
    int rc, s;
    fd_set readfds;

    while (1){
        FD_ZERO(&readfds);
        FD_SET(websock, &readfds);
        int highest = websock;

        for (l = clientsockets; l; l = l->next) {
            s = *((int*)l->val);
            FD_SET(s, &readfds);
            highest = max(highest, s);
        }

        rc = select(highest + 1, &readfds, 0, 0, NULL);
        if (rc < 0) {
            cperror("select");
            continue;
        }

        if (rc == 0)
            continue;

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
    }
    pthread_cleanup_pop(1);
}

void *rec_thread(void *_){
    rec_running = 1;
    pthread_cleanup_push(cleaner, &rec_running);
    pthread_setcanceltype(PTHREAD_CANCEL_ENABLE, 0);
    fd_set readfds;
    int rc;
    size_t i, number_recv = 1;

    while (1){
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        rc = select(sock + 1, &readfds, 0, 0, 0);

        if (rc < 0) {
            cperror("select");
            continue;
        }

        if (rc == 0)
            continue;

        if (FD_ISSET(sock, &readfds)) {
            for (i = 0; i < number_recv; i++)
                if (handle_reception() == -1){
                    if (number_recv > neighbours->size + 1)
                        number_recv--;
                    break;
                }

            if (i == number_recv && number_recv < 2 * neighbours->size)
                number_recv++;
        }
    }
    pthread_cleanup_pop(1);
}

void *send_thread(void *_){
    send_running = 1;
    pthread_cleanup_push(cleaner, &send_running);
    pthread_setcanceltype(PTHREAD_CANCEL_ENABLE, 0);
    int size;
    message_t *msg;
    struct timeval tv = { 0 };

    while (1) {
        tv.tv_sec = MAX_TIMEOUT;
        tv.tv_usec = 0;

        size = hello_neighbours(&tv);
        if (size < MAX_NB_NEIGHBOUR)
            hello_potential_neighbours(&tv);

        message_flooding(&tv);
        neighbour_flooding(0);

        while((msg = pull_message())) {
            send_message(sock, msg, &tv);
            free_message(msg);
        }

        clean_old_data();
        clean_old_frags();

        sleep(tv.tv_sec);
    }

    pthread_cleanup_pop(1);
}

#define BUFFER_INPUT_SIZE 4096
void *input_thread(void *_){
    input_running = 1;
    pthread_cleanup_push(cleaner, &input_running);
    pthread_setcanceltype(PTHREAD_CANCEL_ENABLE, 0);

    int rc;
    char buffer[BUFFER_INPUT_SIZE] = { 0 };

    while (1){
        rc = read(0, buffer, BUFFER_INPUT_SIZE);

        if (rc < 0){
            cperror("read stdin");
            continue;
        }

        if (rc == 0){ // end of stdin reached
            int *ret = malloc(1);
            *ret = 0;
            pthread_exit(ret);
        }

        handle_input(buffer, rc);
    }

    pthread_cleanup_pop(1);
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

    signal(SIGINT, quit_handler);
    cprint(STDOUT_FILENO, "%s\n", SEPARATOR);

    void *ret;

    pthread_t *thread_id[4] = {&web_pt, &rec_pt, &send_pt, &input_pt};
    char *runnings[4] = {&web_running, &rec_running, &send_running, &input_running};
    void *(*starters[4])(void*) = {web_thread, rec_thread, send_thread, input_thread};

    for (int i = 0; i < 4; i++){
        rc = pthread_create(thread_id[i], 0, starters[i], 0);
        if (rc != 0){
            cperror("Could not create initial threads.\n");
            return 1;
        }
    }

    while (1) {
        pthread_mutex_lock(&mutex_end_thread);
        pthread_cond_wait(&cond_end_thread, &mutex_end_thread);

        for (int i = 0; i < 4; i++)
            if (*runnings[i] == 0){
                pthread_join(*thread_id[i], &ret);
                if (*(int*)ret == 0) // normal shutdown
                    return 0;

                free(ret);

                cprint(STDERR_FILENO, "A thread was stopped, trying to restart it\n");
                rc = pthread_create(thread_id[i], NULL, starters[i], NULL);
                if (rc){
                    sleep(5);
                    rc = pthread_create(thread_id[i], NULL, starters[i], NULL);
                    if (rc){
                        cprint(STDERR_FILENO, "Could not restart the thread.\n");
                        return 1;
                    }
                }
                cprint(STDERR_FILENO, "Thread successfully restarted\n");
            }

        pthread_mutex_unlock(&mutex_end_thread);
    }
}
