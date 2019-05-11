#define _GNU_SOURCE

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>

#include "utils.h"
#include "network.h"
#include "tlv.h"
#include "interface.h"
#include "websocket.h"
#include "onsend.h"
#include "flooding.h"

// user address
struct sockaddr_in6 local_addr;

/**
 * Generic network functions
 *
 */

#define MAXSIZE ((1 << 16) + 4)
int handle_reception () {
    u_int8_t c[MAXSIZE] = { 0 };
    size_t len = MAXSIZE;
    struct sockaddr_in6 addr = { 0 };

    int rc = recv_message(sock, &addr, c, &len);
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

    cprint(0, "Received message : magic %d, version %d, size %d\n",
           msg->magic, msg->version, msg->body_length);

    if (msg->magic != MAGIC)
        cprint(STDERR_FILENO, "Invalid magic value\n");
    else if (msg->version != VERSION)
        cprint(STDERR_FILENO, "Invalid version\n");
    else
        handle_tlv(msg->body, n);

     free_message(msg);

    return 0;
}

int recv_message(int sock, struct sockaddr_in6 *addr, u_int8_t *out, size_t *buflen) {
    if (!out || !buflen) return 0;

    struct in6_pktinfo *info = 0;
    struct iovec iov[1];
    struct msghdr hdr = { 0 };
    union {
        unsigned char cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
        struct cmsghdr align;
    } u;

    iov[0].iov_base = out;
    iov[0].iov_len = *buflen;

    hdr.msg_name = addr;
    hdr.msg_namelen = sizeof(*addr);
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = (struct cmsghdr*)u.cmsgbuf;
    hdr.msg_controllen = sizeof(u.cmsgbuf);

    int rc = recvmsg(sock, &hdr, 0);
    if (rc < 0) return errno;
    *buflen = rc;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&hdr);
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
        cprint(STDERR_FILENO, "IPV6_PKTINFO non trouvé\n");
        return -2;
    }

    char ipstr[INET6_ADDRSTRLEN], myipstr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr->sin6_addr, ipstr, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &info->ipi6_addr, myipstr, INET6_ADDRSTRLEN);
    cprint(0, "Receive message from (%s, %u) on interface (%s, %d) .\n",
           ipstr, ntohs(addr->sin6_port), myipstr, info->ipi6_ifindex);

    return 0;
}

size_t message_to_iovec(message_t *msg, struct iovec **iov_dest) {
    body_t *p;
    ssize_t i;

    int nb = 1;
    for (p = msg->body; p; p = p->next)
        nb++;

    struct iovec *iov = calloc(nb, sizeof(struct iovec));
    if (!iov)
        return 0;
    *iov_dest = iov;

    iov[0].iov_base = msg;
    iov[0].iov_len = 4;

    for (i = 1, p = msg->body; p; p = p->next, i++) {
        iov[i].iov_base = p->content;
        iov[i].iov_len = p->size;
    }

    return i;
}

int bytes_to_message(const u_int8_t *src, size_t buflen, neighbour_t *n, message_t *msg) {
    if (msg == NULL || n == NULL || src == NULL) return -8;
    int rc = check_message_size(src, buflen);
    if (rc < 0) return rc;

    u_int16_t size;
    memcpy(&size, src + 2, sizeof(size));
    size = ntohs(size);

    if (size == 0)
        return -9;

    msg->magic = src[0];
    msg->version = src[1];
    msg->body_length = size;
    msg->body = 0;
    msg->dst = n;

    size_t i = 4;
    body_t *body, *bptr;

    while (i < buflen) {
        body = create_body();
        if (!body){
            cperror("malloc");
            break;
        }

        if (src[i] == BODY_PAD1) body->size = 1;
        else body->size = 2 + src[i + 1];

        body->content = voidndup(src + i, body->size);

        if (!body->content){
            cperror("malloc");
            free(body);
            body = 0;
            break;
        }

        i += body->size;

        if (!msg->body) msg->body = body;
        else bptr->next = body;
        bptr = body;
    }

    if (i < buflen){ // loop exit with break
        for (body = msg->body; body; body = bptr){
            bptr = body->next;
            free(body->content);
            free(body);
        }
        return -10;
    }

    return 0;
}

int start_server(int port) {
    int rc, s;
    memset(&local_addr, 0, sizeof(local_addr));

    s = socket(PF_INET6, SOCK_DGRAM, 0);
    if (s < 0 ) {
        cperror("socket");
        return -1;
    }

    rc = fcntl(s, F_GETFL);
    if (rc < 0) {
        cperror("fnctl");
        return -1;
    }

    rc = fcntl(s, F_SETFL, rc | O_NONBLOCK);
    if (rc < 0) {
        cperror("fnctl");
        return -1;
    }

    local_addr.sin6_family = AF_INET6;
    local_addr.sin6_port = htons(port);

    char out[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &local_addr, out, INET6_ADDRSTRLEN);
    if (local_addr.sin6_port)
        cprint(0, "Start server at %s on port %d.\n", out, ntohs(local_addr.sin6_port));
    else
        cprint(0, "Start server at %s on a random port.\n", out);

    int num = 1;
    rc = setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &num, sizeof(num));
    if (rc < 0) {
        cperror("setsockopt");
        return -3;
    }

    num = 0;
    rc = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &num, sizeof(num));
    if (rc < 0) {
        cperror("setsockopt");
        return -3;
    }

    num = 1;
    rc = setsockopt(s, IPPROTO_IPV6, IPV6_DONTFRAG, &num, sizeof(num));
    if (rc < 0) {
        cperror("setsockopt");
        return -3;
    }

    rc = bind(s, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if (rc < 0) {
        cperror("bind");
        return -2;
    }

    return s;
}

/**
 * Quit handler
 */
void quit_handler (int sig) {
    int rc;
    size_t i;
    list_t *l;
    char ipstr[INET6_ADDRSTRLEN];
    message_t msg = { 0 };
    body_t goaway = { 0 };
    struct timespec tv = { 0 };

    cprint(0, "Send go away leave to neighbours before quit.\n");

    rc = tlv_goaway(&goaway.content, GO_AWAY_LEAVE, "Bye !", 5);
    if (rc >= 0){
        goaway.size = rc;

        msg.magic = MAGIC;
        msg.version = VERSION;
        msg.body_length = goaway.size;
        msg.body = &goaway;

        for (i = 0; i < neighbours->capacity; i++) {
            for (l = neighbours->tab[i]; l; l = l->next) {
                msg.dst = (neighbour_t*)l->val;
                rc = send_message(sock, &msg, &tv);
                if (rc != 0) {
                    perrorbis(rc, "send_message");
                    cprint(STDERR_FILENO, "Failed to send goaway to (%s, %u).\n", ipstr, ntohs(msg.dst->addr->sin6_port));
                }
            }
        }

        free(goaway.content);
    }

    close(sock);
    close(websock);

    for (l = clientsockets; l; l = l->next) {
        rc = *((int*)l->val);
        // TODO : send close frame
        close(rc);
    }

    cprint(STDOUT_FILENO, "Bye.\n");
    exit(sig);
}
