#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>

#include "tlv.h"
#include "types.h"
#include "utils.h"
#include "network.h"
#include "tlv.h"
#include "innondation.h"

#define MIN_PORT 1024
#define MAX_PORT 49151

int init() {
    int rc;
    rc = init_random();
    if (rc < 0) {
        perror("init");
        return 1;
    }

    return init_network();
}

int main(int argc, char **argv) {
    int rc;

    rc = init();
    if (rc != 0) return rc;
    printf("local id: %lu\n", id);

    unsigned short port = 0;
    if (argc >= 2){
        char *pos = 0;
        long int port2 = strtol(argv[1], &pos, 0);
        if (argv[1] != NULL && *pos == '\0' && port2 >= MIN_PORT && port2 <= MAX_PORT) {
            port = (unsigned short)port2;
        }
    }

    sock = start_server(port);
    if (sock < 0) {
        fprintf(stderr, "coudn't create socket\n");
        return 1;
    }

    rc = add_neighbour("jch.irif.fr", "1212", &potential_neighbours);

    if (rc < 0) {
        perror("add neighbour");
        return 2;
    }

    int size;
    struct timeval tv = { 0 };
    message_t msg = { 0 };

    while (1) {
        size = hello_neighbours(sock, &tv);
        if (size < 8) {
            printf("You have %d friends, try to find new ones.\n", size);
            hello_potential_neighbours(sock);
        }

        printf("\n\n");

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        rc = select(sock + 1, &readfds, 0, 0, &tv);
        if (rc < 0) {
            perror("select");
            continue;
        }

        if (rc == 0 || !FD_ISSET(sock, &readfds))
            continue;

        char c[4096] = { 0 };
        size_t len = 4096;
        struct sockaddr_in6 addr = { 0 };
        rc = recv_message(sock, &addr, c, &len);
        if (rc < 0) {
            if (errno == EAGAIN)
                continue;
            perror("receive message");
            continue;
        }

        // maybe unnecessary
        memset(&msg, 0, sizeof(message_t));
        rc = bytes_to_message(c, len, &msg);
        if (rc == 0){
            printf("Message description:\n");
            printf("magic: %d\n", msg.magic);
            printf("version: %d\n", msg.version);
            printf("body length: %d\n\n", msg.body_length);
            handle_tlv(msg.body, &addr);

            free_message(&msg);
        } else {
            fprintf(stderr, "Error decripting the message : %d\n", rc);
        }
    }

    printf("Bye !\n");

    return 0;
}
