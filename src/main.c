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
#include <getopt.h>
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
#include "threads.h"
#include "signals.h"

#define MIN_PORT 1024
#define MAX_PORT 49151

static int port = 0, pseudo_set = 0;

static pthread_cond_t initiate_cond(){
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    return cond;
}

int init() {
    init_random();
    id = random_uint64();

    globalnum = 0;

    rl_catch_signals = 0;

    neighbours = hashset_init();
    if (neighbours == NULL)
        return -1;

    potential_neighbours = hashset_init();
    if (potential_neighbours == NULL){
        hashset_destroy(neighbours);
        return -1;
    }

    if (httpport == 0)
        httpport = (rand() % 10) + 8080;
    clientsockets = 0;
    webmessage_map = hashmap_init(sizeof(int));

    sprintf(tmpdir, "chat_%lx", random_uint64());
    char fptmpdir[1024];
    sprintf(fptmpdir, "/tmp/%s", tmpdir);
    int rc = mkdir(fptmpdir, 0722);
    if (rc < 0) {
        cperror("mkdir");
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

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    // to avoid any deadlock

    pthread_mutex_init(&globalnum_mutex, &attr);
    pthread_mutex_init(&mutex_end_thread, &attr);
    send_cond = initiate_cond();
    cond_end_thread = initiate_cond();

    pthread_mutex_init(&write_mutex, &attr);
    pthread_mutex_init(&queue_mutex, &attr);
    pthread_mutex_init(&clientsockets_mutex, &attr);
    pthread_mutexattr_destroy(&attr);

    pthread_mutexattr_destroy(&attr);

    pmtu_map = hashmap_init(18);
    if (!pmtu_map) {
        hashset_destroy(neighbours);
        hashset_destroy(potential_neighbours);
        hashmap_destroy(flooding_map, 0);
        hashmap_destroy(data_map, 0);
        hashmap_destroy(fragmentation_map, 0);
        return -1;
    }
    return 0;
}

#define NBOPT 4
static struct option options[] =
    {
     {"port",     required_argument, 0, 0},
     {"web-port", required_argument, 0, 0},
     {"logs",     required_argument, 0, 0},
     {"pseudo",   required_argument, 0, 0},
     {0, 0, 0, 0}
    };

static int opt_port(char *arg) {
    if (!is_number(arg)) {
        fprintf(stderr, "Port must be a number. %s is not a number.\n", arg);
        return -1;
    }

    port = atoi(arg);
    if (port < 1024) {
        fprintf(stderr, "Not a valid port number %d\n", port);
        return -1;
    }

    return 0;
}

static int opt_webport(char *port) {
    if (!is_number(port)) {
        fprintf(stderr, "Web port must be a number. %s is not a number.\n", port);
        return -1;
    }

    httpport = atoi(port);
    if (httpport < 1024) {
        fprintf(stderr, "Not a valid port number %d\n", httpport);
        return -1;
    }

    return 0;
}

static int opt_log(char *file) {
    if (file) {
        int fd = open(file, O_CREAT|O_WRONLY, 0644);
        if (fd < 0) {
            cperror("open");
        } else {
            printf("Logs are in %s.\n", file);
            logfd = fd;
        }
    }

    return 0;
}

static int opt_pseudo(char *name) {
    if (strlen(name) == 0) {
        fprintf(stderr, "Pseudo can't be empty,\n");
        return -1;
    }

    setPseudo(name, strlen(name));
    pseudo_set = 1;
    return 0;
}

static int (*option_handlers[NBOPT])(char *) =
    {
     opt_port,
     opt_webport,
     opt_log,
     opt_pseudo
    };

static const char *usage =
    "usage: %s [-l[file] | --logs <log file>]\n"
    "%*s[-p | -port <port number>]\n"
    "%*s[--web-port <port number>]\n"
    "%*s[--pseudo <pseudo>]\n";

int parse_args(int argc, char **argv) {
    int rc, c, option_index, padding;
    logfd = 2;

    while (1) {

        c = getopt_long(argc, argv, "p:l:", options, &option_index);

        if (c == -1)
            break;

        switch(c) {
        case 0:
            rc = option_handlers[option_index](optarg);
            break;

        case 'p':
            rc = opt_port(optarg);
            break;

        case 'l':
            rc = opt_log(optarg);
            break;

        default:
            padding = 8 + strlen(argv[0]);
            printf(usage, argv[0], padding, padding, padding);
            return -1;
        }

        if (rc < 0) {
            return rc;
        }
    }

    return 0;
}

int main(int argc, char **argv) {
    int rc;

    rc = init();
    if (rc != 0) return rc;

    rc = parse_args(argc, argv);
    if (rc < 0) return rc;

    if (!pseudo_set) setRandomPseudo();

    cprint(STDOUT_FILENO, "Welcome %s.\n", getPseudo());

    sock = start_server(port);
    if (sock < 0) {
        cprint(STDERR_FILENO, "coudn't create socket\n");
        return 1;
    }

    websock = create_tcpserver(httpport);
    if (websock < 0) {
        fprintf(stderr, "Error while creating web server.\n");
        return 1;
    }

    cprint(STDOUT_FILENO, "Web interface on http://localhost:%d.\n", httpport);

    struct sigaction sigact = { 0 };

    sigact.sa_sigaction = crit_err_hdlr;
    sigact.sa_flags = SA_RESTART | SA_SIGINFO;

    if (sigaction(SIGINT, &sigact, (struct sigaction *)NULL) != 0) {
        fprintf(stderr, "error setting signal handler for %d (%s)\n",
        SIGINT, strsignal(SIGINT));
        exit(EXIT_FAILURE);
    }

    cprint(STDOUT_FILENO, "%s\n", SEPARATOR);

    void *ret = NULL;

    pthread_t *thread_id[NUMBER_THREAD] = {&web_pt, &rec_pt, &send_pt, &input_pt};
    char *runnings[NUMBER_THREAD] = {&web_running, &rec_running, &send_running, &input_running};
    void *(*starters[NUMBER_THREAD])(void*) = {web_thread, rec_thread, send_thread, input_thread};

    rc = launch_threads();
    if (rc != 0)
        goto quit;

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
