#define _GNU_SOURCE

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
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

// user address
struct sockaddr_in6 local_addr;

/**
 * Generic network functions
 *
 */

int handle_reception () {
    int rc;
    u_int8_t c[4096] = { 0 };
    size_t len = 4096;
    struct sockaddr_in6 addr = { 0 };

    rc = recv_message(sock, &addr, c, &len);
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

    cprint(0, "Received message : magic %d, version %d, size %d\n", msg->magic, msg->version, msg->body_length);

    if (msg->magic != MAGIC) {
        cprint(STDERR_FILENO, "Invalid magic value\n");
    } else if (msg->version != VERSION) {
        cprint(STDERR_FILENO, "Invalid version\n");
    } else {
        handle_tlv(msg->body, n);
    }

    free_message(msg);
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
        body = malloc(sizeof(body_t));
        if (!body){
            cperror("malloc");
            break;
        }

        memset(body, 0, sizeof(body_t));

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
    rc = bind(s, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if (rc < 0) {
        cperror("bind");
        return -2;
    }

    char out[INET6_ADDRSTRLEN];
    assert (inet_ntop(AF_INET6, &local_addr, out, INET6_ADDRSTRLEN) != NULL);
    if (local_addr.sin6_port)
        cprint(0, "Start server at %s on port %d.\n", out, ntohs(local_addr.sin6_port));
    else
        cprint(0, "Start server at %s on a random port.\n", out);

    int one = 1;
    rc = setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
    if (rc < 0) {
        cperror("setsockopt");
        return -3;
    }

    return s;
}


/**
 *
 * Neighbour initialisation function
 *
 */

neighbour_t *
new_neighbour(const unsigned char ip[sizeof(struct in6_addr)],
              unsigned int port, const neighbour_t *tutor) {
    struct sockaddr_in6 *addr = malloc(sizeof(struct sockaddr_in6));
    if (addr == NULL){
        cperror("malloc");
        return 0;
    }
    memset(addr, 0, sizeof(struct sockaddr_in6));
    addr->sin6_family = AF_INET6;
    addr->sin6_port = port;
    memcpy(addr->sin6_addr.s6_addr, ip, sizeof(struct in6_addr));

    neighbour_t *n = malloc(sizeof(neighbour_t));
    if (n == NULL){
        cperror("malloc");
        free(addr);
        return 0;
    }

    memset(n, 0, sizeof(neighbour_t));
    n->pmtu = DEF_PMTU;
    n->short_hello_count = 0;
    n->addr = addr;
    n->last_neighbour_send = time(0);
    assert (n->last_neighbour_send != -1);
    n->status = NEIGHBOUR_POT;
    n->tutor_id = 0;

    if (tutor) {
        n->tutor_id = malloc(18);
        /* doesn't matter if tutor_id is null, at worst we don't send a warning */

        if (n->tutor_id)
            bytes_from_neighbour(tutor, n->tutor_id);
    }

    int rc = hashset_add(potential_neighbours, n);
    if (rc == 2){
        cprint(0, "Tried to add a neighbour to potentials but it was already in.\n");
        free(n->tutor_id);
        free(n->addr);
        free(n);
    } else if (rc == 0)
        perrorbis(ENOMEM, "hashset_add");
    return hashset_get(potential_neighbours, ip, port);
}

int add_neighbour(const char *hostname, const char *service) {
    int rc, s;
    char ipstr[INET6_ADDRSTRLEN] = { 0 };
    struct addrinfo hints = { 0 }, *r = NULL;
    struct sockaddr_in6 *addr;

    hints.ai_family = PF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_V4MAPPED | AI_ALL;

    rc = getaddrinfo (hostname, service, &hints, &r);
    if (rc != 0){
        cprint(0, "getaddrinfo: %s\n", gai_strerror(rc));
        perrorbis(rc, "getaddrinfo: %s\n");
        return rc;
    }

    for (struct addrinfo *p = r; p != NULL; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0)
            continue;
        close(s);


        addr = (struct sockaddr_in6*)p->ai_addr;
        if (!new_neighbour(addr->sin6_addr.s6_addr, addr->sin6_port, 0))
            continue;

        assert (inet_ntop(AF_INET6, &addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
        cprint(0, "Add %s, %d to potential neighbours\n", ipstr, ntohs(addr->sin6_port));
    }

    freeaddrinfo(r);

    return 0;
}

int recv_message(int sock, struct sockaddr_in6 *addr, u_int8_t *out, size_t *buflen) {
    if (!out || !buflen) return 0;

    int rc;
    struct in6_pktinfo *info = 0;
    struct iovec iov[1];
    struct msghdr hdr = { 0 };
    struct cmsghdr *cmsg;
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

    rc = recvmsg(sock, &hdr, 0);
    if (rc < 0) return errno;
    *buflen = rc;

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
        cprint(STDERR_FILENO, "IPV6_PKTINFO non trouvé\n");
        return -2;
    }

    char ipstr[INET6_ADDRSTRLEN];
    assert (inet_ntop(AF_INET6, &addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
    cprint(0, "Receive message from (%s, %u).\n", ipstr, ntohs(addr->sin6_port));

    return 0;
}

void quit_handler (int sig) {
    int rc;
    size_t i;
    list_t *l;
    char ipstr[INET6_ADDRSTRLEN];
    message_t msg = { 0 };
    body_t goaway = { 0 };
    struct timeval tv = { 0 };

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
                    assert (inet_ntop(AF_INET6, &msg.dst->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
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
