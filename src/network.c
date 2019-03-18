#define _GNU_SOURCE

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "network.h"

// user address
struct sockaddr_in6 local_addr;

int init_network() {
    id = random_uint64();
    neighbours = 0;
    return 0;
}

size_t message_to_iovec(message_t *msg, struct iovec **iov_dest, ssize_t nb) {
    body_t *p;
    ssize_t i;
    struct iovec *iov;

    nb = (nb << 1) + 1;
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

int add_neighbour(char *hostname, char *service, neighbour_t **neighbour) {
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

    struct sockaddr *copy = malloc(p->ai_addrlen);
    if (copy == NULL) return -3;
    memcpy(copy, p->ai_addr, p->ai_addrlen);

    neighbour_t *n = malloc(sizeof(neighbour_t));
    if (n == NULL) return -4;

    n->id = 0;
    n->last_hello = 0;
    n->last_long_hello = 0;
    n->addr = copy;
    n->addrlen = p->ai_addrlen;
    n->next = *neighbour;
    *neighbour = n;

    freeaddrinfo(r);

    return 0;
}

int send_message(neighbour_t *neighbour, int sock, message_t *msg, size_t nb_body) {
    int rc;
    struct msghdr hdr = { 0 };
    struct in6_pktinfo info;

    hdr.msg_name = neighbour->addr;
    hdr.msg_namelen = neighbour->addrlen;
    hdr.msg_iovlen = message_to_iovec(msg, &hdr.msg_iov, nb_body);
    if (!hdr.msg_iov) return -1;

    memset(&info, 0, sizeof(info));
    info.ipi6_addr = local_addr.sin6_addr;

    rc = sendmsg(sock, &hdr, MSG_NOSIGNAL);
    free(hdr.msg_iov);
    // free might change errno but prevents a memory leak
    // find a way to avoid using free here ?
    if (rc < 0) return -2;

    return 0;
}

int recv_message(int sock, struct in6_addr *addr, char *out, size_t *buflen) {
    int rc;
    unsigned char buf[4096];
    struct in6_pktinfo *info = 0;
    struct iovec iov[1];
    struct msghdr hdr;
    struct cmsghdr *cmsg;
    union {
        unsigned char cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
        struct cmsghdr align;
    } u;

    iov[0].iov_base = buf;
    iov[0].iov_len = 4096;
    memset(&hdr, 0, sizeof(hdr));

    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = (struct cmsghdr*)u.cmsgbuf;
    hdr.msg_controllen = sizeof(u.cmsgbuf);

    rc = recvmsg(sock, &hdr, 0);
    if (rc < 0) return -1;

    cmsg = CMSG_FIRSTHDR(&hdr);
    while(cmsg) {
        if ((cmsg->cmsg_level == IPPROTO_IPV6) &&
            (cmsg->cmsg_type == IPV6_PKTINFO)) {
            info = (struct in6_pktinfo*)CMSG_DATA(cmsg);
            break;
        }
        cmsg = CMSG_NXTHDR(&hdr, cmsg);
    }

    if(info == NULL) {
        /* ce cas ne devrait pas arriver */
        fprintf(stderr, "IPV6_PKTINFO non trouvé\n");
    }

    *addr = info->ipi6_addr;

    char ipstr[128];
    const char *p = inet_ntop(AF_INET6, &info->ipi6_addr, ipstr, 128);
    if (!p) { // weird
        perror("inet");
    } else {
        printf("Receive message from %s.\n", ipstr);
    }

    if (!out || !buflen) return 0;
    if (*buflen > iov[0].iov_len) *buflen = iov[0].iov_len;
    memcpy(out, buf, *buflen);
    return 0;
}

message_t* bytes_to_message(void *src, size_t buflen) {
    message_t *msg = malloc(sizeof(message_t));
    if (!msg) return 0;

    size_t i = 0;
    body_t *body, *bptr;

    if (buflen < 4) return 0;

    msg->magic = *((type_t*)src);
    msg->version = *((type_t*)src + 1);
    msg->body_length = ntohs(*((u_int16_t*)(src + 2)));
    msg->body = 0;

    void *buf = src + 4;

    while (i < msg->body_length && i < buflen) {
        body = malloc(sizeof(body_t));

        body->type = *((type_t*)buf + i++);
        if (body->type == BODY_PAD1) continue;

        body->length = *((type_t*)buf + i++);

        // TODO: from big endian to host
        body->content = malloc(body->length);
        memcpy(body->content, buf + i, body->length);
        i += body->length;
        body->next = 0;

        // TODO: find something better
        if (!msg->body) {
            msg->body = body;
            bptr = body;
        }  else {
            bptr->next = body;
            bptr = body;
        }
    }

    return msg;
}

int start_server(int port) {
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

    char out[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &local_addr, out, INET6_ADDRSTRLEN) == 0){
        // both errors from inet_ntop aren't possible here but you never know
        perror("inet_ntop");
    } else {
        printf("Start server at %s on port %d.\n", out, local_addr.sin6_port);
    }

    int one = 1;
    rc = setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
    if (rc < 0) {
        perror("setsockopt");
        return -3;
    }

    return s;
}
