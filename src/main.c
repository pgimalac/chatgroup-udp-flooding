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
    int rc;
    rc = init_random();
    if (rc < 0) {
        perror("init random");
        return 1;
    }
    rc = init_network();
    if (rc < 0) {
        perror("init network");
        return 2;
    }

    flooding_map = hashmap_init(12);
    data_map = hashmap_init(12);

    return 0;
}

void handle_reception () {
    int rc;
    u_int8_t c[4096] = { 0 };
    size_t len = 4096;
    struct sockaddr_in6 addr = { 0 };
    message_t *msg = 0;
    neighbour_t *n = 0;

    rc = recv_message(sock, &addr, c, &len);
    if (rc < 0) {
        if (errno == EAGAIN)
            return;
        perror("receive message");
        return;
    }

    n = hashset_get(neighbours,
                    addr.sin6_addr.s6_addr,
                    addr.sin6_port);

    if (!n) {
        n = hashset_get(potential_neighbours,
                        addr.sin6_addr.s6_addr,
                        addr.sin6_port);
    }

    if (!n) {
        n = new_neighbour(addr.sin6_addr.s6_addr,
                          addr.sin6_port);
        dprintf(logfd, "Add to potential neighbours.\n");
    }

    msg = bytes_to_message(c, len, n);
    if (!msg){
        fprintf(stderr, "Error decripting the message : %d\n", rc);
        return;
    }

    dprintf(logfd, "Received message : magic %d, version %d, size %d\n", msg->magic, msg->version, msg->body_length);

    if (msg->magic != MAGIC) {
        fprintf(stderr, "Invalid magic value\n");
    } else if (msg->version != VERSION) {
        fprintf(stderr, "Invalid version\n");
    } else {
        handle_tlv(msg->body, n);
    }

    free_message(msg);
}

void handle_input() {
    int rc;
    char buffer[512] = { 0 };

    rc = read(0, buffer, 511);
    if (rc < 0) {
        perror("read stdin");
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
    dprintf(logfd, "local id: %lx\n", id);

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

    printf("Welcome %s.\n", getPseudo());

    sock = start_server(port);
    if (sock < 0) {
        fprintf(stderr, "coudn't create socket\n");
        return 1;
    }

    printf("================================\n\n");

    int size;
    message_t *msg;
    struct timeval tv = { 0 };

    while (1) {
        size = hello_neighbours(&tv);
        if (size < 8) {
            hello_potential_neighbours(&tv);
        }

        message_flooding(&tv);
        neighbour_flooding(0);

        while((msg = pull_message())) {
            send_message(sock, msg);
            free_message(msg);
        }

        dprintf(logfd, "Timeout before next send loop %ld.\n\n", tv.tv_sec);

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        FD_SET(0, &readfds);

        rc = select(sock + 1, &readfds, 0, 0, &tv);
        if (rc < 0) {
            perror("select");
            continue;
        }

        if (rc == 0)
            continue;

        if (FD_ISSET(sock, &readfds)) {
            handle_reception();
        } else if (FD_ISSET(0, &readfds)) {
            handle_input();
        }
    }

    printf("Bye !\n");

    return 0;
}
