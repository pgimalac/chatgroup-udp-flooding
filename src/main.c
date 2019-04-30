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

#include "tlv.h"
#include "types.h"
#include "utils.h"
#include "network.h"
#include "interface.h"
#include "tlv.h"
#include "flooding.h"

#define MIN_PORT 1024
#define MAX_PORT 49151

#define COMMAND '/'

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

    flooding_map = hashmap_init(12);
    if (flooding_map == NULL){
        hashmap_destroy(flooding_map, 0);
        return -1;
    }
    data_map = hashmap_init(12);
    if (data_map == NULL){
        hashmap_destroy(data_map, 0);
        return -1;
    }
    fragmentation_map = hashmap_init(12);
    if (fragmentation_map == NULL){
        hashmap_destroy(fragmentation_map, 0);
        return -1;
    }

    return 0;
}

int handle_reception () {
    int rc;
    u_int8_t c[4096] = { 0 };
    size_t len = 4096;
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

void handle_input() {
    int rc;
    char buffer[4096] = { 0 };

    rc = read(0, buffer, 4096);
    if (rc < 0) {
        cperror("read stdin");
        return;
    }

    if (rc <= 1)
        return;

    int tmp = strspn(buffer, forbiden);
    char *bufferbis = buffer + tmp;
    rc -= tmp;

    while (rc > 0 && strchr(forbiden, bufferbis[rc - 1]) != NULL)
        rc--;

    if (bufferbis[0] == COMMAND) handle_command(bufferbis + 1);
    else send_data(bufferbis, rc);
}

int main(int argc, char **argv) {
    int rc;

    rc = init();
    if (rc != 0) return rc;
    cprint(0, "local id: %lx\n", id);

    signal(SIGINT, quit_handler);

    unsigned short port = 0;
    if (argc > 1){
        char *pos = 0;
        long int port2 = strtol(argv[1], &pos, 0);
        if (argv[1] != NULL && *pos == '\0' && port2 >= MIN_PORT && port2 <= MAX_PORT) {
            port = (unsigned short)port2;
        }
    }

    if (argc >= 3)
        setPseudo(argv[2]);
    else
        setRandomPseudo();

    cprint(STDOUT_FILENO, "Welcome %s.\n", getPseudo());

    sock = start_server(port);
    if (sock < 0) {
        cprint(STDERR_FILENO, "coudn't create socket\n");
        return 1;
    }

    cprint(STDOUT_FILENO, "%s\n", SEPARATOR);

    int size;
    message_t *msg;
    struct timeval tv = { 0 };

    size_t number_recv = 1, i;

    while (1) {
        size = hello_neighbours(&tv);
        if (size < MAX_NB_NEIGHBOUR) {
            hello_potential_neighbours(&tv);
        }

        message_flooding(&tv);
        neighbour_flooding(0);

        while((msg = pull_message())) {
            send_message(sock, msg, &tv);
            free_message(msg);
        }

        clean_old_data();
        clean_old_frags();
        cprint(0, "Timeout before next send loop %ld.\n\n", tv.tv_sec);

        fd_set readfds;
        fd_set done;
        FD_ZERO(&readfds);
        FD_ZERO(&done);
        FD_SET(sock, &readfds);
        FD_SET(0, &readfds);

        rc = select(sock + 1, &readfds, 0, 0, &tv);
        if (rc < 0) {
            cperror("select");
            continue;
        }

        if (rc == 0)
            continue;

        if (FD_ISSET(0, &readfds))
            handle_input();

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
