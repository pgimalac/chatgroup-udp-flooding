#include <stdio.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>

#include <sys/stat.h>
#include <fcntl.h>

#include "network.h"
#include "tlv.h"
#include "flooding.h"
#include "utils.h"
#include "structs/list.h"
#include "interface.h"
#include "utils.h"

void hello_potential_neighbours(struct timeval *tv) {
    int rc;
    size_t i;
    time_t max, delta, now = time(0);
    assert(now != -1);
    list_t *l;
    neighbour_t *p;
    body_t *hello;
    char ipstr[INET6_ADDRSTRLEN];

    list_t *to_delete = NULL;

    for (i = 0; i < potential_neighbours->capacity; i++) {
        for (l = potential_neighbours->tab[i]; l != NULL; l = l->next) {
            p = (neighbour_t*)l->val;

            if (p->short_hello_count >= NBSH) {
                assert (inet_ntop(AF_INET6, &p->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
                cprint(0, "Remove (%s, %u) from potential neighbour list.\n",
                       ipstr, ntohs(p->addr->sin6_port));
                cprint(0, "He did not answer to short hello for too long.\n");

                if (list_add(&to_delete, p) == 0){
                    cperror("list_add");
                }
                continue;
            }

            delta = now - p->last_hello_send;
            max = 1 << (p->short_hello_count + 4);

            if (delta >= max) {
                hello = malloc(sizeof(body_t));
                if (hello == NULL){
                    cperror("malloc");
                    continue;
                }

                rc = tlv_hello_short(&hello->content, id);
                if (rc < 0){
                    cperror("tlv_hello_short");
                    free(hello);
                    continue;
                }
                hello->size = rc;

                rc = push_tlv(hello, p);
                if (rc < 0) {
                    cprint(STDERR_FILENO, "Could not insert short hello into message queue\n");
                    free(hello->content);
                    free(hello);
                }
            } else if (max - delta < tv->tv_sec) {
                tv->tv_sec = max - delta;
            }
        }
    }

    while (to_delete != NULL){
        neighbour_t *n = list_pop(&to_delete);

        if (n->tutor_id) {
            neighbour_t *m = hashset_get(neighbours, n->tutor_id, *(u_int16_t*)(n->tutor_id + 16));
            char msg[256] = { 0 };
            if (m) {
                hello = malloc(sizeof(body_t));
                if (hello){
                    assert (inet_ntop(AF_INET6, n->addr->sin6_addr.s6_addr,
                                  ipstr, INET6_ADDRSTRLEN) != NULL);

                    sprintf(msg, "You recommended (%s, %u) but I can't reach it.",
                            ipstr, ntohs(*(u_int16_t*)(n->tutor_id + 16)));
                    cprint(0, "%s\n", msg);

                    hello->size = tlv_warning(&hello->content, msg, strlen(msg));
                    push_tlv(hello, m);
                } else
                    cperror("malloc");
            }
        }

        if (!hashset_remove_neighbour(potential_neighbours, n))
            cprint(STDERR_FILENO, "%s:%d Tried to remove a potential neighbour but it wasn't in the potential neighbour set.\n");
        free(n->addr);
        free(n->tutor_id);
        free(n);
    }
}

int hello_neighbours(struct timeval *tv) {
    neighbour_t *p;
    int rc;
    size_t i, size = 0;
    time_t now = time(0), delta;
    assert(now != -1);

    list_t *l, *to_delete = 0;
    char ipstr[INET6_ADDRSTRLEN];
    tv->tv_sec = MAX_TIMEOUT;
    tv->tv_usec = 0;

    for (i = 0; i < neighbours->capacity; i++) {
        for (l = neighbours->tab[i]; l; l = l->next, size++) {
            p = (neighbour_t*)l->val;
            if (now - p->last_hello < SYM_TIMEOUT) {
                delta = now - p->last_hello_send;
                if (delta >= MAX_TIMEOUT) {
                    body_t *hello = malloc(sizeof(body_t));
                    if (hello == NULL){
                        cperror("malloc");
                        continue;
                    }

                    rc = tlv_hello_long(&hello->content, id, p->id);
                    if (rc < 0){
                        cperror("tlv_hello_long");
                        free(hello);
                        continue;
                    }
                    hello->size = rc;

                    rc = push_tlv(hello, p);
                    if (rc < 0) {
                        cprint(STDERR_FILENO, "Could not insert long hello into message queue\n");
                        free(hello->content);
                        free(hello);
                    }
                } else if (MAX_TIMEOUT - delta < tv->tv_sec) {
                    tv->tv_sec = MAX_TIMEOUT - delta;
                }
            } else if (list_add(&to_delete, p) == 0){
                cperror("list_add");
            }
        }
    }

    while (to_delete) {
        p = (neighbour_t*)list_pop(&to_delete);
        if (!hashset_remove(neighbours, p->addr->sin6_addr.s6_addr, p->addr->sin6_port))
            cprint(STDERR_FILENO, "%s:%d Tried to remove a neighbour that wasn't actually one.\n",
                __FILE__, __LINE__);
        rc = hashset_add(potential_neighbours, p);
        if (rc == 2)
            cprint(STDERR_FILENO, "%s:%d Tried to add to potentials a neighbour that was already in.\n",
                __FILE__, __LINE__);
        else if (rc == 0){
            perrorbis(ENOMEM, "hashset_add");
            free(p->addr);
            free(p->tutor_id);
            free(p);
            return -1;
        }

        assert (inet_ntop(AF_INET6, &p->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
        cprint(0, "Remove (%s, %u) from neighbour list and add to potential neighbours.\n",
            ipstr, ntohs(p->addr->sin6_port));
        cprint(0, "He did not send long hello for too long \n");
    }

    return size;
}
