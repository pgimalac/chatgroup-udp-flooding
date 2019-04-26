#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <network.h>
#include <arpa/inet.h>

#include "types.h"
#include "commands.h"
#include "innondation.h"
#include "pseudo.h"

static const char *usages[] = {
    "add <addr> <port>",
    "name <name>",
    "print",
    "juliusz",
    "neighbour"
    "quit",
};

static void add(char *buffer){
    int rc;
    char *name = 0, *service = 0;
    name = strtok(buffer, " ");
    service = strtok(0, " \n");
    if (!name || !service) {
        fprintf(stderr, "Usage: %s\n", usages[0]);
        return;
    }

    printf("Add %s, %s to potential neighbours\n", name, service);
    rc = add_neighbour(name, service);
    if (rc < 0) {
        perror("add neighbour");
    }
}

static void name(char *buffer){
    buffer += strspn(buffer, forbiden);
    int len = strlen(buffer);
    while (len > 0 && strchr(forbiden, buffer[len - 1]) != NULL)
        len--;

    if (len > PSEUDO_LENGTH){
        printf("Nickname too long.\n");
    } else if (len < 3){
        printf("Nickname too short\n");
    } else {
        buffer[len] = '\0';
        setnickname(buffer, len);
        printf("Nickname set to \"%s\"\n", buffer);
    }
}

static void __print(const neighbour_t *n){
    if (n != NULL && n->addr != NULL){
        char ipstr[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &n->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL){
            printf("    @ %s / %d\n", ipstr, ntohs(n->addr->sin6_port));
            return;
        }
    }
    printf("    Could not display.\n");
}

static void print(char *buffer){
    if (hashset_isempty(neighbours)){
        printf("You have no neighbour\n");
    } else {
        printf("You have %lu neighbour%s:\n", neighbours->size, neighbours->size == 1 ? "" : "s");
        hashset_iter(neighbours, __print);
    }
    if (hashset_isempty(potential_neighbours)){
        printf("You have no potential_neighbour.\n");
    } else {
        printf("You have %lu potential neighbour%s:\n", potential_neighbours->size,
                    potential_neighbours->size == 1 ? "" : "s");
        hashset_iter(potential_neighbours, __print);
    }
    printf("\n");
}

static void juliusz(char *buffer){
    char j[] = "jch.irif.fr 1212";
    // on appelle strtok sur la chaine dans add
    // donc on doit pouvoir modifier la chaine,
    // d'où le tableau et pas un pointeur
    add(j);
}

static void neighbour(char *buffer){
    neighbour_innondation();
}

static void quit(char *buffer){
    printf("Bye.\n");
    exit(0);
}

static void unknown(char *buffer){
    printf("Usage:\n");
    for (const char **usage = usages; *usage; usage++)
        printf("    %s\n", *usage);
}

static const char *names[] = {
    "add", "name", "print", "juliusz", "neighbour", "quit", NULL
};

static void (*commands[])(char*) = {
    add, name, print, juliusz, neighbour, quit, NULL
};


void handle_command(char *buffer) {
    char *ins = strpbrk(buffer, " \n");
    int ind;
    if (ins != NULL)
        for (ind = 0; names[ind] != NULL; ind ++)
            if (strncasecmp(buffer, names[ind], strlen(names[ind])) == 0){
                commands[ind](ins);
                break;
            }

    if (ins == NULL || names[ind] == NULL)
        unknown(buffer);
}
