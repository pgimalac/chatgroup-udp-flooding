#define _GNU_SOURCE

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "network.h"
#include "tlv.h"

// user address
struct sockaddr_in6 local_addr;

int init_network() {
    id = random_uint64();
    neighbours = 0;
    potential_neighbours = 0;
    return 0;
}

size_t message_to_iovec(message_t *msg, struct iovec **iov_dest) {
    body_t *p;
    ssize_t i;
    struct iovec *iov;

    int nb = 1;
    for (p = msg->body; p; p = p->next)
        nb++;

    iov = calloc(nb, sizeof(struct iovec));
    if (!iov) return 0;
    *iov_dest = iov;

    iov[0].iov_base = msg;
    iov[0].iov_len = 4;

    for (i = 1, p = msg->body; p; p = p->next, i++) {
        iov[i].iov_base = p->content;
        iov[i].iov_len = p->size;
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
    hints.ai_flags = AI_V4MAPPED;

    rc = getaddrinfo (hostname, service, &hints, &r);
    if (rc < 0 || r == 0) return -1;

    for (p = r;
         (0 != p) && ((s = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) <= 0);
         p = p->ai_next);
    close(s);

    if (p == 0) return -2;

    struct sockaddr_in6 *copy = malloc(sizeof(struct sockaddr_in6));
    if (copy == NULL) return -3;
    memset(copy, 0, sizeof(struct sockaddr_in6));
    memmove(copy, p->ai_addr, p->ai_addrlen);

    neighbour_t *n = malloc(sizeof(neighbour_t));
    if (n == NULL){
        free(copy);
        return -4;
    }

    n->id = 0;
    n->last_hello = 0;
    n->last_long_hello = 0;
    n->last_hello_send = 0;
    n->addr = copy;
    n->next = *neighbour;
    *neighbour = n;

    freeaddrinfo(r);

    return 0;
}

int send_message(neighbour_t *neighbour, int sock, message_t *msg) {
    int rc;
    struct msghdr hdr = { 0 };
    struct in6_pktinfo info;

    hdr.msg_name = neighbour->addr;
    hdr.msg_namelen = sizeof(struct sockaddr_in6);
    hdr.msg_iovlen = message_to_iovec(msg, &hdr.msg_iov);
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

int recv_message(int sock, struct sockaddr_in6 *addr, char *out, size_t *buflen) {
    int rc;
    unsigned char buf[4096];
    struct in6_pktinfo *info = 0;
    struct iovec iov[1];
    struct msghdr hdr = { 0 };
    struct cmsghdr *cmsg;
    union {
        unsigned char cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
        struct cmsghdr align;
    } u;

    iov[0].iov_base = buf;
    iov[0].iov_len = 4096;

    hdr.msg_name = addr;
    hdr.msg_namelen = sizeof(*addr);
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
        return -2;
    }

    char ipstr[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) == 0){
        perror("inet_ntop");
    } else {
        printf("Receive message from %s.\n", ipstr);
    }

    if (!out || !buflen) return 0;
    *buflen = rc;
    memcpy(out, buf, *buflen);
    return 0;
}

int check_message_size(const char* buffer, int buflen){
    if (buffer == NULL)
        return BUFNULL;
    if (buflen < 4)
        return BUFSH;

    u_int16_t body_length = be16toh(*(u_int16_t*)(buffer + 2));
    if (body_length + 4 != buflen)
        return BUFINC;
    int i = 4, body_num = 0, rc;
    while (i < buflen){
        i++;
        if (buffer[i - 1] != BODY_PAD1){
            if (i >= buflen)
                return TLVSH;
            i += 1 + (u_int8_t)buffer[i];
        }
        body_num ++;
    }

    if (i != buflen)
        return SUMLONG;

    i = 4;
    while (i < buflen){
        rc = check_tlv_size(buffer + i);
        assert(rc != 0);
        if (rc < 0)
            return rc;
        i += rc;
    }

    return body_num;
}

int bytes_to_message(const char *src, size_t buflen, message_t *msg) {
    if (msg == NULL)
        return -6;
    int rc = check_message_size(src, buflen);
    if (rc < 0) return rc;

    size_t i = 4;
    body_t *body, *bptr;

    msg->magic = src[0];
    msg->version = src[1];
    msg->body_length = ntohs(*(u_int16_t*)(src + 2));
    msg->body = 0;

    if (msg->body_length == 0)
        return 0;

    while (i < buflen) {
        body = malloc(sizeof(body_t));
        if (!body){ // todo : better error handling
            perror("malloc");
            break;
        }
        memset(body, 0, sizeof(body_t));

        if (src[i] == BODY_PAD1) body->size = 1;
        else body->size = 2 + src[i + 1];
        body->content = malloc(body->size);
        if (!body->content){ // todo : better error handling
            perror("malloc");
            free(body);
            body = 0;
            break;
        }
        memcpy(body->content, src + i, body->size);
        i += body->size;

        // TODO: find something better
        if (!msg->body) msg->body = body;
        else bptr->next = body;
        bptr = body;
    }

    if (i < buflen){ // loop exit with break
        free_message(msg, FREE_BODY);
        return -7;
    }

    return 0;
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
        if (local_addr.sin6_port)
            printf("Start server at %s on port %d.\n", out, ntohs(local_addr.sin6_port));
        else
            printf("Start server at %s on a random port.\n", out);
    }

    int one = 1;
    rc = setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
    if (rc < 0) {
        perror("setsockopt");
        return -3;
    }

    return s;
}
