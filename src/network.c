#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "utils.h"
#include "network.h"

int
init_network() {
    id = random_uint64();
    neighbours = 0;
    return 0;
}

struct iovec *
message_to_iovec(message_t *msg, size_t *nb_body) {
    struct iovec *iov;
    body_t *p;
    size_t i;

    *nb_body = (*nb_body) * 2 + 1;
    iov = malloc((*nb_body) * sizeof(struct iovec));
    if (!iov) return 0;

    iov[0].iov_base = msg;
    iov[0].iov_len = 4;

    for (i = 1, p = msg->body; p; p = p->next, i++) {
        iov[i].iov_base = p;
        iov[i].iov_len = BODY_H_SIZE;
        i++;
        iov[i].iov_base = p->content;
        iov[i].iov_len = p->length;
    }

    return iov;
}


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


    return 0;
}
