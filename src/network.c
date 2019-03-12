#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "utils.h"

chat_id_t id;
neighbour_t *neighbours;

int
init_network() {
    id = random_uint64();
    neighbours = 0;
    return 0;
}

// HAS NOT BEEN TESTED YET
int
send_hello(char *hostname, char *service) {
    int rc, s;
    struct addrinfo hints, *r, *p;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    hints.ai_flags = 0;

    rc = getaddrinfo (hostname, service, &hints, &r);
    if (rc < 0) return -1;

    for (p = r;
         p != 0 && (s = socket(p->ai_family, p->ai_socktype, p->ai_protocol) <= 0);
         p = p->ai_next);

    if (p == 0) return -2;
    freeaddrinfo(r);

    struct hello_msg hello = { 0 };
    hello.source_id = htons(id);

    message_t msg = {0};
    msg.hdr.type = HELLO;
    msg.hdr.length = 8;

    rc = sendto(s, &msg, sizeof(char) * 10, 0, 0, 0);
    if (rc < 0) {
        perror("sendto:");
        return -3;
    }

    rc = recvfrom(s, &msg, sizeof(char) * 26, 0, 0, 0);
    if (rc < 0) {
        perror("recvfom:");
        return -4;
    }

    return 0;
}
