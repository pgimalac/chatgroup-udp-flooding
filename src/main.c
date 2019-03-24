#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>

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


int on_recv(char *c, size_t buflen, struct sockaddr_in6 *addr) {
    int rc;
    message_t msg;
    char *warning;

    rc = bytes_to_message(c, buflen, &msg);
    if (rc < 0) return -1;

    //printf("Message description:\n");
    //printf("magic: %d\n", msg.magic);
    //printf("version: %d\n", msg.version);
    //printf("body length: %d\n\n", msg.body_length);

    for(body_t *p = msg.body; p; p = p->next) {
        //printf("Next TLV\n");
        printf("type: %d\n", p->content[0]);
        printf("length: %d\n", p->content[1]);
        switch(p->content[0]) {
        case BODY_HELLO:
            update_hello((chat_id_t*)(p->content + 2),
                         p->content[1] / sizeof(chat_id_t),
                         addr);
            break;
        case BODY_NEIGHBOUR:
            update_neighbours((struct in6_addr*)(p->content + 2),
                              *((u_int16_t*)(p->content + 18)));
            break;
        case BODY_WARNING:
            warning = malloc(p->content[1] + 1);
            memset(warning, 0, p->content[1] + 1);
            memmove(warning, p->content + 2, p->content[1]);
            printf("Warning Message: %s\n", warning);
            free(warning);
            break;
        }
    }

    free_message(&msg);
    return 0;
}

int main(int argc, char **argv) {
    int rc, s;

    rc = init();
    if (rc != 0) return rc;
    printf("%lu\n", id);

    unsigned short port = 0;
    if (argc >= 2){
        char *pos = 0;
        long int port2 = strtol(argv[1], &pos, 0);
        printf("%ld\n", port2);
        if (argv[1] != NULL && *pos == '\0' && port2 >= MIN_PORT && port2 <= MAX_PORT){
            printf("ok\n");
            port = (unsigned short)port2;
        }
    }

    s = start_server(port);
    if (s < 0) {
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
    while (1) {
        size = hello_neighbours(s, &tv);
        if (size < 8)
            hello_potential_neighbours(s);

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(s, &readfds);
        rc = select(s + 1, &readfds, 0, 0, &tv);
        if (rc < 0) {
            perror("select");
            continue;
        }

        if (rc == 0 || !FD_ISSET(s, &readfds))
            continue;

        char c[4096] = { 0 };
        size_t len = 4096;
        struct sockaddr_in6 addr = { 0 };
        rc = recv_message(s, &addr, c, &len);
        if (rc < 0) {
            if (errno == EAGAIN)
                continue;
            perror("receive message");
            continue;
        }

        rc = on_recv(c, len, &addr);
        if (rc < 0) {
            fprintf(stderr, "Corrupted message.\n");
        }
    }

    printf("Bye !\n");

    return 0;
}
