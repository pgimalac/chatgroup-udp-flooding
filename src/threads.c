#include <signal.h>
#include <stdio.h>
#include <readline/readline.h>
#include <arpa/inet.h>
#include <errno.h>

#include "threads.h"
#include "signals.h"
#include "structs/list.h"
#include "websocket.h"
#include "utils.h"
#include "network.h"
#include "flooding.h"
#include "interface.h"
#include "tlv.h"
#include "onsend.h"

pthread_t *thread_id[NUMBER_THREAD] =
    {
     &web_pt,
     &rec_pt,
     &send_pt,
     &input_pt
    };

char *runnings[NUMBER_THREAD] =
    {
     &web_running,
     &rec_running,
     &send_running,
     &input_running
    };

void *(*starters[NUMBER_THREAD])(void*) =
    {
     web_thread,
     rec_thread,
     send_thread,
     input_thread
    };

int launch_threads(){
    for (int i = 0; i < NUMBER_THREAD; i++){
        *runnings[i] = 0;
        int rc = pthread_create(thread_id[i], 0, starters[i], runnings[i]);
        if (rc != 0){
            cperror("Could not create initial threads.\n");
            return 1;
        }
    }
    return 0;
}

void *web_thread(void *running) {
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

    while (1){
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        rc = select(sock + 1, &readfds, 0, 0, 0);

        if (rc < 0) {
            cperror("select");
            continue;
        }

        if (rc == 0 || !FD_ISSET(sock, &readfds))
            continue;

        while (handle_reception() != -1){}
    }

    pthread_cleanup_pop(1);
}

void *send_thread(void *running){
    *(char*)running = 1;
    pthread_cleanup_push(cleaner, running);
    pthread_setcanceltype(PTHREAD_CANCEL_ENABLE, 0);
    int size, rc;
    message_t *msg;
    struct timespec tv = { 0 };
    pthread_mutex_t useless = PTHREAD_MUTEX_INITIALIZER;
    char ipstr[INET6_ADDRSTRLEN];


//    time_t start;
    while (1) {
        tv.tv_sec = time(0) + MAX_TIMEOUT;

        size = hello_neighbours(&tv);
        if (size < MAX_NB_NEIGHBOUR){
            hello_potential_neighbours(&tv);
        }

        message_flooding(&tv);
        neighbour_flooding(0);

        while((msg = pull_message())) {
            rc = send_message(sock, msg, &tv);
            if (rc == EAFNOSUPPORT || rc == ENETUNREACH){
                hashset_remove_neighbour(potential_neighbours, msg->dst);
                hashset_remove_neighbour(neighbours, msg->dst);
                inet_ntop(AF_INET6, msg->dst->addr->sin6_addr.s6_addr,
                          ipstr, INET6_ADDRSTRLEN);
                cprint(0, "Could not reach (%s, %u) so it was removed from the neighbours.\n",
                    ipstr, msg->dst->addr->sin6_port);
                free(msg->dst->addr);
                free(msg->dst->tutor_id);
                free(msg->dst);
            } else if (rc == EMSGSIZE)
                cprint(0, "Message is too large.\n");
            else if (rc != 0)
                perrorbis(rc, "SENDMSG");
            free_message(msg);
        }

        decrease_pmtu();
        clean_old_data();
        clean_old_frags();

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

    char cpy[1 << 16], *buffer, *line;
    while (1) {
        line = readline("");

        if (line == NULL){ // end of stdin reached
            int *ret = malloc(sizeof(int));
            *ret = 0;
            pthread_exit(ret);
        }

        size_t len = strlen(line);
        buffer = purify(line, &len);
        if (len == 0 || buffer == NULL){
            free(line);
            continue;
        }

        if (buffer[0] != COMMAND) {
            const char *p = getPseudo();
            len += strlen(p) + 2;
            snprintf(cpy, 1 << 16, "%s: %s", p, buffer);
        } else
            memcpy(cpy, buffer, len);
        free(line);

        #define S "\e1M\e[1A\e[K"

        write(STDOUT_FILENO, S, strlen(S));

        print_message((u_int8_t*)cpy, len);
        handle_input(cpy, len);

        write(STDOUT_FILENO, CLBEG, strlen(CLBEG));
        fsync(STDOUT_FILENO);
    }

    pthread_cleanup_pop(1);
}
