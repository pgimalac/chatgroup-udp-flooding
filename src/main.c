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
#include <getopt.h>

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

static int port = 0, pseudo_set = 0;

int init() {
    nonce = 1;

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

    if (httpport == 0)
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

    pmtu_map = hashmap_init(18);
    if (!pmtu_map) {
        hashset_destroy(neighbours);
        hashset_destroy(potential_neighbours);
        hashmap_destroy(flooding_map, 0);
        hashmap_destroy(data_map, 0);
        hashmap_destroy(fragmentation_map, 0);
        return -1;
    }

    interfaces = 0;

    return 0;
}

#define MAXSIZE ((1 << 16) + 4)
int handle_reception () {
    int rc;
    u_int8_t c[MAXSIZE] = { 0 };
    size_t len = MAXSIZE;
    struct sockaddr_in6 addr = { 0 };

    rc = recv_message(sock, &addr, c, &len);
    if (rc != 0) {
        if (errno == EAGAIN)
            return -1;
        cperror("receive message");
        return -2;
    }

    neighbour_t *n = hashset_get(neighbours,
                    addr.sin6_addr.s6_addr,
                    addr.sin6_port);

    if (!n) {
        n = hashset_get(potential_neighbours,
                        addr.sin6_addr.s6_addr,
                        addr.sin6_port);
    }

    if (!n) {
        n = new_neighbour(addr.sin6_addr.s6_addr,
                          addr.sin6_port, 0);
        if (!n){
            cprint(0, "An error occured while trying to create a new neighbour.\n");
            return -4;
        }
        cprint(0, "Add to potential neighbours.\n");
    }

    message_t *msg = malloc(sizeof(message_t));
    if (!msg){
        cperror("malloc");
        return -5;
    }
    memset(msg, 0, sizeof(message_t));
    rc = bytes_to_message(c, len, n, msg);
    if (rc != 0){
        cprint(0, "Received an invalid message.\n");
        handle_invalid_message(rc, n);
        free(msg);
        return -3;
    }

    cprint(0, "Received message : magic %d, version %d, size %d\n", msg->magic, msg->version, msg->body_length);

    if (msg->magic != MAGIC) {
        cprint(STDERR_FILENO, "Invalid magic value\n");
    } else if (msg->version != VERSION) {
        cprint(STDERR_FILENO, "Invalid version\n");
    } else {
        handle_tlv(msg->body, n);
    }

    free_message(msg);
    return 0;
}

void handle_stdin_input() {
    int rc;
    char buffer[4096] = { 0 };
    rc = read(0, buffer, 4096);

    if (rc < 0){
        cperror("read stdin");
        return;
    }

    if (rc == 0)
        quit_handler(0);

    size_t len = rc;
    purify(buffer, &len);
    if (buffer[0] != '/') {
        char tmp[6000];
        rc = sprintf(tmp, "%s: %s", getPseudo(), buffer);
        if (rc < 0) {
            perror("sprintf");
            return;
        }
        memcpy(buffer, tmp, rc);
        len = rc;
    }

    handle_input(buffer, len);
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
            perror("open");
            logfd = 2;
        } else {
            printf("Logs are in %s.\n", file);
            logfd = fd;
        }
    }

    return 0;
}

static int opt_pseudo(char *name) {
    if (strlen(name) == 0) {
        fprintf(stderr, "Pseudo cannot be empty,\n");
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
            printf(usage, argv[0], padding, "", padding, "");
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

    logfd = 2;

    rc = init();
    if (rc != 0) return rc;

    rc = parse_args(argc, argv);
    if (rc < 0) return rc;

    if (!pseudo_set) setRandomPseudo();

    cprint(0, "local id: %lx\n", id);

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

    signal(SIGINT, quit_handler);
    cprint(STDOUT_FILENO, "%s\n", SEPARATOR);

    int size;
    message_t *msg;
    struct timeval tv = { 0 };
    char ipstr[INET6_ADDRSTRLEN];

    size_t number_recv = 1, i;

    while (1) {
        size = hello_neighbours(&tv);
        if (size < MAX_NB_NEIGHBOUR) {
            hello_potential_neighbours(&tv);
        }

        message_flooding(&tv);
        neighbour_flooding(0);

        while((msg = pull_message())) {
            rc = send_message(sock, msg, &tv);
            if (rc == EAFNOSUPPORT || rc == ENETUNREACH){
                inet_ntop(AF_INET6, msg->dst->addr->sin6_addr.s6_addr,
                          ipstr, INET6_ADDRSTRLEN);
                cprint(0, "Could not reach (%s, %u) so it was removed from the neighbours.\n",
                       ipstr, htons(msg->dst->addr->sin6_port));
                remove_neighbour(msg->dst);
            } else if (rc == EMSGSIZE) {
                cprint(0, "Message is too large.\n");
            } else if (rc != 0) {
                perrorbis(rc, "SENDMSG");
            }
            free_message(msg);
        }

        decrease_pmtu();
        clean_old_data();
        clean_old_frags();
        cprint(0, "Timeout before next send loop %ld.\n\n", tv.tv_sec);

        fd_set readfds;
        list_t *l, *to_delete = 0;
        void *val;
        int s, max = sock > websock ? sock : websock;

        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        FD_SET(websock, &readfds);
        FD_SET(0, &readfds);

        for (l = clientsockets; l; l = l->next) {
            s = *((int*)l->val);
            FD_SET(s, &readfds);
            if (s > max) max = s;
        }

        rc = select(max + 1, &readfds, 0, 0, &tv);
        if (rc < 0) {
            cperror("select");
            continue;
        }

        if (rc == 0)
            continue;

        if (FD_ISSET(0, &readfds))
            handle_stdin_input();

        if (FD_ISSET(websock, &readfds)) {
            handle_http();
        }

        for (l = clientsockets; l; l = l->next) {
            s = *((int*)l->val);
            if (FD_ISSET(s, &readfds)) {
                rc = handle_ws(s);
                if (rc < 0) {
                    list_add(&to_delete, l->val);
                }
            }
        }

        while (to_delete) {
            val = list_pop(&to_delete);
            list_eremove(&clientsockets, val);
        }

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

    cprint(STDOUT_FILENO, "Bye !\n");

    return 0;
}
