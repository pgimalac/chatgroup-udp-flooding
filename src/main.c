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
#include "commands.h"
#include "tlv.h"
#include "innondation.h"

#define MIN_PORT 1024
#define MAX_PORT 49151

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

    char buffer[30] = { 0 };
    while (1){
        printf("Enter your nickname (between 3 and 30 characters) : ");
        fflush(stdout);

        rc = read(1, buffer, 30);
        fflush(stdin);
        if (rc < 0){
            perror("init nickname read");
            return 3;
        } else if (rc < 3)
            fprintf(stderr, "Too short.\n");
        else{
            setnickname(buffer, rc);
            break;
        }
    }

    return 0;
}

void handle_reception () {
    int rc;
    char c[4096] = { 0 };
    size_t len = 4096;
    struct sockaddr_in6 addr = { 0 };
    message_t *msg = 0;

    rc = recv_message(sock, &addr, c, &len);
    if (rc < 0) {
        if (errno == EAGAIN)
            return;
        perror("receive message");
        return;
    }

    msg = bytes_to_message(c, len);
    if (msg){
        printf("Message description:\n");
        printf("magic: %d\n", msg->magic);
        printf("version: %d\n", msg->version);
        printf("body length: %d\n\n", msg->body_length);

        if (msg->magic != 93) {
            fprintf(stderr, "Invalid magic value\n");
        } else if (msg->version != 2) {
            fprintf(stderr, "Invalid version\n");
        } else {
            handle_tlv(msg->body, &addr);
        }

        free_message(msg, FREE_BODY);
    } else {
        fprintf(stderr, "Error decripting the message : %d\n", rc);
    }
}

void handle_input() {
    int rc;
    char buffer[512] = { 0 };

    rc = read(0, buffer, 511);
    if (rc < 0) {
        perror("read stdin");
        return;
    }
    if (rc == 0)
        return;

    if (buffer[0] == '@')
        handle_command(buffer + 1);
    else
        send_data(buffer, rc);
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


    if (rc < 0) {
        perror("add neighbour");
        return 2;
    }

    int size;
    message_t *msg;
    struct timeval tv = { 0 };

    while (1) {
        size = hello_neighbours(&tv);
        if (size < 8) {
            printf("You have %d friends, try to find new ones.\n", size);
            hello_potential_neighbours();
        }

        while((msg = pull_message())) {
            send_message(sock, msg);
            free_message(msg, FREE_BODY);
        }

        printf("\n\n");

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
