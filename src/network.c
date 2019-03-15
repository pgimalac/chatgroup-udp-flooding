#define _GNU_SOURCE

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

// user address
struct sockaddr_in6 local_addr;

int
init_network() {
    id = random_uint64();
    neighbours = 0;
    return 0;
}

size_t
message_to_iovec(message_t *msg, struct iovec **iov_dest, ssize_t nb) {
    body_t *p;
    ssize_t i;
    struct iovec *iov;

    nb = (nb + 1) << 1;
    iov = malloc(nb * sizeof(struct iovec));
    if (!iov) return 0;
    *iov_dest = iov;

    iov[0].iov_base = msg;
    iov[0].iov_len = 4;

    for (i = 1, p = msg->body; p; p = p->next, i++) {
        iov[i].iov_base = p;
        iov[i].iov_len = BODY_H_SIZE;
        i++;
        iov[i].iov_base = p->content;
        iov[i].iov_len = p->length;
    }

    return i;
}

int
add_neighbour(char *hostname, char *service,
              neighbour_t **neighbour) {
    int rc, s;
    struct addrinfo hints, *r, *p;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    hints.ai_flags = 0;

    rc = getaddrinfo (hostname, service, &hints, &r);
    if (rc < 0 || r == 0) return -1;

    for (p = r;
         (0 != p) && ((s = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) <= 0);
         p = p->ai_next);
    close(s);

    if (p == 0) return -2;

    neighbour_t *n = malloc(sizeof(neighbour_t));
    if (!n) return -3;
    n->id = 0;
    n->last_hello = 0;
    n->last_long_hello = 0;
    n->addr = p->ai_addr;
    n->addrlen = p->ai_addrlen;
    n->next = *neighbour;
    *neighbour = n;

    freeaddrinfo(r);

    return 0;
}

int
send_message(neighbour_t *neighbour, int sock,
             message_t *msg, size_t nb_body) {
    int rc;
    struct msghdr hdr = { 0 };
    struct cmsghdr *cmsg;
    struct in6_pktinfo info;

    union {
        char cmsgbuf[CMSG_SPACE(sizeof(info))];
        struct cmsghdr align;
    } u;

    hdr.msg_name = neighbour->addr;
    hdr.msg_namelen = neighbour->addrlen;
    hdr.msg_iovlen = message_to_iovec(msg, &hdr.msg_iov, nb_body);
    if (!hdr.msg_iov) return -1;

    memset(&info, 0, sizeof(info));
    info.ipi6_addr = local_addr.sin6_addr;

    memset(u.cmsgbuf, 0, sizeof(u.cmsgbuf));
    hdr.msg_control = u.cmsgbuf;
    hdr.msg_controllen = sizeof(u.cmsgbuf);

    cmsg = CMSG_FIRSTHDR(&hdr);
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    memcpy(CMSG_DATA(cmsg), &info, sizeof(struct in6_pktinfo));

    rc = sendmsg(sock, &hdr, 0);
    if (rc < 0) return -2;

    return 0;
}


int
start_server(int port) {
    int rc, s;
    memset(&local_addr, 0, sizeof(struct sockaddr_in6));

    s = socket(PF_INET6, SOCK_DGRAM, 0);
    if (s < 0 ) {
        perror("socket");
        return -1;
    }

    local_addr.sin6_family = AF_INET6;
    local_addr.sin6_port = htons(port);
    rc = bind(s, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if (rc < 0) {
        perror("bind");
        return -2;
    }

    char out[4000];
    inet_ntop(AF_INET6, &local_addr, out, sizeof(local_addr));
    printf("Start server at %s on port %d.\n", out, local_addr.sin6_port);

    int one = 1;
    rc = setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
    if (rc < 0) {
        perror("setsockopt");
        return -3;
    }

    return s;
}
