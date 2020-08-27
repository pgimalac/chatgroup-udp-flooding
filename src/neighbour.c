#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "flooding.h"
#include "interface.h"
#include "network.h"
#include "structs/list.h"
#include "tlv.h"
#include "utils.h"

/**
 *
 * Neighbour initialisation function
 *
 */

neighbour_t *new_neighbour(const unsigned char ip[sizeof(struct in6_addr)],
                           unsigned int port, const neighbour_t *tutor) {
    pthread_mutex_lock(&neighbours->mutex);
    pthread_mutex_lock(&potential_neighbours->mutex);

    char ipstr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip, ipstr, INET6_ADDRSTRLEN);
    if (hashset_contains(neighbours, ip, port)) {
        cprint(0, "Neighbour (%s, %u) already known (symetrical).\n", ipstr,
               ntohs(port));
        pthread_mutex_unlock(&potential_neighbours->mutex);
        pthread_mutex_unlock(&neighbours->mutex);
        return 0;
    } else if (hashset_contains(potential_neighbours, ip, port)) {
        cprint(0, "Neighbour (%s, %u) already known (potential_neighbours).\n",
               ipstr, ntohs(port));
        pthread_mutex_unlock(&potential_neighbours->mutex);
        pthread_mutex_unlock(&neighbours->mutex);
        return 0;
    } else if (max(neighbours->size, potential_neighbours->size) >=
               MAX_NB_NEIGHBOUR) {
        cprint(0,
               "Already too much neighbours so (%s, %u) wasn't added in the "
               "potentials.\n",
               ipstr, ntohs(port));
        pthread_mutex_unlock(&potential_neighbours->mutex);
        pthread_mutex_unlock(&neighbours->mutex);
        return 0;
    }

    struct sockaddr_in6 *addr = malloc(sizeof(struct sockaddr_in6));
    if (addr == NULL) {
        cperror("malloc");
        pthread_mutex_unlock(&potential_neighbours->mutex);
        pthread_mutex_unlock(&neighbours->mutex);
        return 0;
    }

    memset(addr, 0, sizeof(struct sockaddr_in6));
    addr->sin6_family = AF_INET6;
    addr->sin6_port = port;
    memcpy(addr->sin6_addr.s6_addr, ip, sizeof(struct in6_addr));

    neighbour_t *n = malloc(sizeof(neighbour_t));
    if (n == NULL) {
        cperror("malloc");
        free(addr);
        pthread_mutex_unlock(&potential_neighbours->mutex);
        pthread_mutex_unlock(&neighbours->mutex);
        return 0;
    }

    time_t now = time(0);

    memset(n, 0, sizeof(neighbour_t));
    n->pmtu = DEF_PMTU;
    n->pmtu_discovery_max = DEF_PMTU << 1;
    n->short_hello_count = 0;
    n->addr = addr;
    n->last_neighbour_send = now;
    n->last_pmtu_discovery = now;
    n->status = NEIGHBOUR_POT;
    n->tutor_id = 0;

    if (tutor) {
        n->tutor_id = malloc(18);
        /* doesn't matter if tutor_id is null, at worst we don't send a warning
         */

        if (n->tutor_id)
            bytes_from_neighbour(tutor, n->tutor_id);
    }

    int rc = hashset_add(potential_neighbours, n);
    if (rc == 2) {
        cprint(
            0,
            "Tried to add a neighbour to potentials but it was already in.\n");
        free(n->tutor_id);
        free(n->addr);
        free(n);
    } else if (rc == 0)
        perrorbis(ENOMEM, "hashset_add");

    pthread_mutex_unlock(&potential_neighbours->mutex);
    pthread_mutex_unlock(&neighbours->mutex);
    pthread_cond_broadcast(&send_cond);

    return hashset_get(potential_neighbours, ip, port);
}

int add_neighbour(const char *hostname, const char *service) {
    int rc, s;
    char ipstr[INET6_ADDRSTRLEN] = {0};
    struct addrinfo hints = {0}, *r = NULL;
    struct sockaddr_in6 *addr;

    hints.ai_family = PF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_V4MAPPED | AI_ALL;

    rc = getaddrinfo(hostname, service, &hints, &r);
    if (rc != 0) {
        cprint(0, "getaddrinfo: %s\n", gai_strerror(rc));
        return rc;
    }

    for (struct addrinfo *p = r; p != NULL; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0)
            continue;
        close(s);

        addr = (struct sockaddr_in6 *)p->ai_addr;
        if (!new_neighbour(addr->sin6_addr.s6_addr, addr->sin6_port, 0))
            continue;

        inet_ntop(AF_INET6, &addr->sin6_addr, ipstr, INET6_ADDRSTRLEN);
        cprint(0, "Add %s, %d to potential neighbours\n", ipstr,
               ntohs(addr->sin6_port));
    }

    freeaddrinfo(r);

    return 0;
}

static int send_neighbour_to(neighbour_t *p) {
    int rc;
    neighbour_t *a;
    body_t *body;

    // this function is called by neighbours_flooding which locks neighbours so
    // no need to lock neighbours here
    for (size_t i = 0; i < neighbours->capacity; i++) {
        for (list_t *l = neighbours->tab[i]; l; l = l->next) {
            a = (neighbour_t *)l->val;
            body = create_body();
            if (!body) {
                cperror("malloc");
                continue;
            }

            rc = tlv_neighbour(&body->content, &a->addr->sin6_addr,
                               a->addr->sin6_port);
            if (rc < 0) {
                free(body);
                cperror("malloc");
                continue;
            }
            body->size = rc;

            rc = push_tlv(body, p);
            if (rc < 0) {
                cprint(STDERR_FILENO,
                       "%s:%d Could not insert data into message queue\n",
                       __FILE__, __LINE__);
                free(body->content);
                free(body);
            }
        }
    }

    char ipstr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &p->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN);
    cprint(0, "Send neighbours to (%s, %u).\n", ipstr,
           ntohs(p->addr->sin6_port));

    return 0;
}

void neighbour_flooding(short force) {
    time_t now = time(0);
    neighbour_t *p;

    pthread_mutex_lock(&neighbours->mutex);

    for (size_t i = 0; i < neighbours->capacity; i++)
        for (list_t *l = neighbours->tab[i]; l; l = l->next) {
            p = (neighbour_t *)l->val;
            if (force || now - p->last_neighbour_send > NEIGHBOUR_TIMEOUT)
                send_neighbour_to(p);
        }

    pthread_mutex_unlock(&neighbours->mutex);
}
