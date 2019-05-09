#include "hashset.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "interface.h"
#include "utils.h"

#define HASHSET_INITIAL_CAPACITY 16
#define HASHSET_RATIO_UPPER_LIMIT 0.8
#define HASHSET_RATIO_LOWER_LIMIT 0.1

#define GET_IP(n) ((neighbour_t*)n)->addr->sin6_addr.s6_addr
#define GET_PORT(n) ((neighbour_t*)n)->addr->sin6_port

hashset_t* hashset_init(){
    hashset_t *h = malloc(sizeof(hashset_t));
    if (h){
        h->size = 0;
        h->capacity = HASHSET_INITIAL_CAPACITY;

        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&h->mutex, &attr);
        pthread_mutexattr_destroy(&attr);

        h->tab = calloc(h->capacity, sizeof(list_t*));
        if (!h->tab){
            free(h);
            h = NULL;
        }
    }
    return h;
}

short hashset_isempty(hashset_t *t) {
    return t->size == 0;
}

static short resize(hashset_t *h, int capacity) {
    list_t** t = calloc(capacity, sizeof(list_t*));
    if (!t) return 0;

    for (size_t i = 0; i < h->capacity; list_destroy(h->tab[i], 0), i++)
        for (list_t* l = h->tab[i]; l != NULL; l = l->next)
            list_add(&t[hash_neighbour_data(GET_IP(l->val), GET_PORT(l->val)) % capacity], l->val);

    free(h->tab);
    h->capacity = capacity;
    h->tab = t;

    return 1;
}

short hashset_contains(hashset_t *h, const u_int8_t ip[sizeof(struct in6_addr)], u_int16_t port){
    return hashset_get(h, ip, port) != NULL;
}

neighbour_t *hashset_get(hashset_t *h, const u_int8_t ip[sizeof(struct in6_addr)], u_int16_t port) {
    if (h == NULL || ip == NULL) return 0;

    pthread_mutex_lock(&h->mutex);

    neighbour_t *ret = NULL;
    for (list_t* l = h->tab[hash_neighbour_data(ip, port) % h->capacity]; l != NULL; l = l->next)
        if (port == GET_PORT(l->val) && memcmp(GET_IP(l->val), ip, sizeof(struct in6_addr)) == 0){
            ret = (neighbour_t*)l->val;
            break;
        }

    pthread_mutex_unlock(&h->mutex);

    return ret;
}

short hashset_add(hashset_t *h, neighbour_t* n){
    if (h == NULL || n == NULL) return 0;

    int ret;

    pthread_mutex_lock(&h->mutex);

    u_int8_t *ip = GET_IP(n);
    u_int16_t port = GET_PORT(n);
    if(hashset_contains(h, ip, port)){
        ret = 2;
    } else {
        if (!list_add(&h->tab[hash_neighbour_data(ip, port) % h->capacity], n))
            ret = 0;
        else {
            h->size++;
            if (h->size > HASHSET_RATIO_UPPER_LIMIT * h->capacity)
                resize(h, h->capacity * 2);
            ret = 1;
        }
    }

    pthread_mutex_unlock(&h->mutex);

    return ret;
}

static void* hashset_list_remove(list_t** l, const u_int8_t ip[sizeof(struct in6_addr)], u_int16_t port){
    if (l == NULL || *l == NULL)
        return NULL;

    if (GET_PORT((*l)->val) == port && memcmp(GET_IP((*l)->val), ip, sizeof(struct in6_addr)) == 0)
        return list_remove(l, 0);

    list_t* tmp;
    for(tmp = *l;
        tmp->next != NULL
            && (GET_PORT(tmp->next->val) != port ||
                memcmp(GET_IP(tmp->next->val), ip, sizeof(struct in6_addr)));
        tmp = tmp->next) ;

    return tmp->next == NULL ? NULL : list_remove(&tmp->next, 0);
}

neighbour_t* hashset_remove_neighbour(hashset_t* h, const neighbour_t *n){
    return hashset_remove(h, GET_IP(n), GET_PORT(n));
}

neighbour_t* hashset_remove(hashset_t *h, const u_int8_t ip[sizeof(struct in6_addr)], u_int16_t port){
    if (h == NULL) return NULL;

    pthread_mutex_lock(&h->mutex);

    int i = hash_neighbour_data(ip, port) % h->capacity;
    neighbour_t *n = hashset_list_remove(&h->tab[i], ip, port);
    if (n != NULL){
        h->size--;
        if (h->size < HASHSET_RATIO_LOWER_LIMIT * h->capacity &&
            h->size > HASHSET_INITIAL_CAPACITY)
            resize(h, h->capacity / 2);
    }

    pthread_mutex_unlock(&h->mutex);

    return n;
}


void hashset_iter(hashset_t *h, void(*f)(const neighbour_t*)) {
    pthread_mutex_lock(&h->mutex);

    for (size_t i = 0; i < h->capacity; i++) {
        if (h->tab[i]) list_iter(h->tab[i], (void(*)(void*))f);
    }

    pthread_mutex_unlock(&h->mutex);
}

void hashset_destroy(hashset_t *h){
    if (h == 0) return;

    pthread_mutex_lock(&h->mutex);

    for (size_t i = 0; i < h->capacity; i++)
        list_destroy(h->tab[i], 1);

    pthread_mutex_unlock(&h->mutex);

    pthread_mutex_destroy(&h->mutex);
    free(h->tab);
    free(h);
}
