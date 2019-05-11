#include <time.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "tlv.h"
#include "onsend.h"
#include "interface.h"
#include "utils.h"
#include "network.h"
#include "tlv.h"

typedef void (*onsend_fnc)(const u_int8_t*, neighbour_t*, struct timespec *tv);

static void onsend_pad1(const u_int8_t *tlv, neighbour_t *dst, struct timespec *tv) {
    cprint(0, "* Containing PAD1\n");
}

static void onsend_padn(const u_int8_t *tlv, neighbour_t *dst, struct timespec *tv) {
    cprint(0, "* Containing Padn %u\n", tlv[1]);
    dst->last_pmtu_discovery = time(0);
}

static void onsend_hello(const u_int8_t *tlv, neighbour_t *dst, struct timespec *tv) {
    dst->last_hello_send = time(0);
    if (tlv[1] == 8) {
        dst->short_hello_count++;
        cprint(0, "* Containing short hello.\n");
    } else {
        cprint(0, "* Containing long hello.\n");
    }
}

static void onsend_neighbour(const u_int8_t *tlv, neighbour_t *dst, struct timespec *tv) {
    cprint(0, "* Containing neighbour.\n");
    dst->last_neighbour_send = time(0);
}

static void onsend_data(const u_int8_t *tlv, neighbour_t *dst, struct timespec *tv) {
    u_int8_t buffer[18];
    time_t now = time(0), delta;

    cprint(0, "* Containing data.\n");

    hashmap_t *map = hashmap_get(flooding_map, tlv + 2);
    if (!map){
        cprint(0, "Data already acked.\n",
            __FILE__, __LINE__);
        return;
    }

    datime_t *datime = hashmap_get(data_map, tlv + 2);
    if (!datime)
        cprint(STDERR_FILENO, "%s:%d Tried to get a tlv from a data_map but it wasn't in.\n", __FILE__, __LINE__);
    else
        datime->last = now;

    bytes_from_neighbour(dst, buffer);
    data_info_t *dinfo = hashmap_get(map, buffer);
    if (!dinfo){
        cprint(0, "Data already acked.\n",
            __FILE__, __LINE__);
        return;
    }

    ++dinfo->send_count;

    if (dinfo->send_count > 1 && dinfo->send_count < 4) {
        msg_pmtu_t *msg_pmtu = hashmap_get(pmtu_map, buffer);
        if (msg_pmtu && memcmp(msg_pmtu->dataid, tlv + 2, 12) == 0) {
            dst->pmtu_discovery_max = (dst->pmtu + dst->pmtu_discovery_max) / 2;
            cprint(0, "Decrease PMTU upper bound to %u.\n", dst->pmtu_discovery_max);
        }
    } else if (dinfo->send_count >= 4) {
        dst->pmtu_discovery_max = (dst->pmtu_discovery_max * 75) / 100;
        cprint(0, "Decrease PMTU upper bound to %u.\n", dst->pmtu);
    }

    time_t delay = (rand() % (1 << (dinfo->send_count + 2))) + (1 << (dinfo->send_count + 1));
    dinfo->time = now + delay;
    delta = dinfo->time - now;

    if (delta < tv->tv_sec - now)
        tv->tv_sec = now + delta;
}

static void onsend_ack(const u_int8_t *tlv, neighbour_t *dst, struct timespec *tv) {
    cprint(0, "* Containing ack.\n");
}

static void onsend_goaway(const u_int8_t *tlv, neighbour_t *dst, struct timespec *tv) {
    cprint(0, "* Containing go away %u.\n", tlv[2]);
}

static void onsend_warning(const u_int8_t *tlv, neighbour_t *dst, struct timespec *tv) {
    cprint(0, "* Containing warning.\n");
}

static void onsend_unknow(const u_int8_t *tlv, neighbour_t *dst, struct timespec *tv) {
    cprint(0, "* Containing an unknow tlv.\n");
}

onsend_fnc onsenders[NUMBER_TLV_TYPE] = {
               onsend_pad1,
               onsend_padn,
               onsend_hello,
               onsend_neighbour,
               onsend_data,
               onsend_ack,
               onsend_goaway,
               onsend_warning
};

int send_message(int sock, message_t *msg, struct timespec *tv) {
    int rc;
    struct msghdr hdr = { 0 };
    body_t *p;
    char ipstr[INET6_ADDRSTRLEN];

    msg->body_length = htons(msg->body_length);

    inet_ntop(AF_INET6, &msg->dst->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN);
    cprint(0, "> Send message to (%s, %u).\n", ipstr, ntohs(msg->dst->addr->sin6_port));

    for (p = msg->body; p; p = p->next) {
        if (p->content[0] >= NUMBER_TLV_TYPE) onsend_unknow(p->content, msg->dst, tv);
        else onsenders[(int)p->content[0]](p->content, msg->dst, tv);
    }

    cprint(0, "\n");

    hdr.msg_name = msg->dst->addr;
    hdr.msg_namelen = sizeof(struct sockaddr_in6);
    hdr.msg_iovlen = message_to_iovec(msg, &hdr.msg_iov);
    if (!hdr.msg_iov || hdr.msg_iovlen == 0)
        return errno;

    rc = sendmsg(sock, &hdr, MSG_NOSIGNAL);
    int err = errno;
    free(hdr.msg_iov);
    msg->body_length = htons(msg->body_length);
    if (rc < 0) return err;

    return 0;
}
