#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <network.h>
#include <arpa/inet.h>
#include <stdlib.h>


#include "types.h"
#include "interface.h"
#include "flooding.h"

char pseudo[PSEUDO_LENGTH + 1];

const int pseudo_length = 25;
const char *pseudos[25] = {
                "Raskolnikov",
                "Mlle Swann",
                "Joshep  K.",
                "Humbert Humbert",
                "Jacopo Belbo",
                "Méphistophélès",
                "Cthulhu",
                "Samsaget Gamgie",
                "Thomas Anderson",
                "Walter White",
                "Wednesday",
                "Morty",
                "Dexter",
                "The eleventh Doctor",
                "Elliot Alderson",
                "Doctor House",
                "Ragnar Lodbrok",
                "Hannibal",
                "Sherlock",
                "Hamlet",
                "King Lear",
                "Zarathustra",
                "Deep Thought",
                "Alcèste",
                "Arthur Dent"
};

// =========== COMMANDS part ===========

static const char *usages[] = {
    "add <addr> <port>",
    "name <name>",
    "random",
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

    rc = add_neighbour(name, service);
    if (rc < 0) {
        perror("add neighbour");
    }
    printf("Add %s, %s to potential neighbours\n", name, service);
}

static void name(char *buffer){
    setPseudo(buffer);
}

static void nameRandom(char *buffer){
    setRandomPseudo();
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
    neighbour_flooding(1);
}

static void quit(char *buffer){
    quit_handler(0);
}

static void unknown(char *buffer){
    printf("Usage:\n");
    for (const char **usage = usages; *usage; usage++)
        printf("    %s\n", *usage);
}

static void chid(char *buffer) {
    id = random_uint64();
}

static const char *names[] =
    {
     "chid",
     "add",
     "name",
     "random",
     "print",
     "juliusz",
     "neighbour",
     "quit",
     NULL
    };

static void (*interface[])(char*) =
    {
     chid,
     add,
     name,
     nameRandom,
     print,
     juliusz,
     neighbour,
     quit,
     NULL
    };


void handle_command(char *buffer) {
    char *ins = strpbrk(buffer, " \n");
    int ind;
    if (ins != NULL)
        for (ind = 0; names[ind] != NULL; ind ++)
            if (strncasecmp(buffer, names[ind], strlen(names[ind])) == 0){
                interface[ind](ins);
                break;
            }

    if (ins == NULL || names[ind] == NULL)
        unknown(buffer);
}

// =========== PSEUDO part ===========

char* getPseudo(){
    return pseudo;
}

void setPseudo(char *buffer){
    buffer += strspn(buffer, forbiden);
    int len = strlen(buffer);
    while (len > 0 && strchr(forbiden, buffer[len - 1]) != NULL)
        len--;

    if (len > PSEUDO_LENGTH){
        printf("Nickname too long.\n");
    } else if (len < 3){
        printf("Nickname too short\n");
    } else {
        for (int i = 0; i < len; i++)
            if (strchr(forbiden, buffer[i]) != NULL)
                buffer[i] = ' ';

        memcpy(pseudo, buffer, len);
        pseudo[len] = '\0';
        printf("Nickname set to \"%s\"\n", pseudo);
    }
}

void setRandomPseudo(){
    int index = rand() % pseudo_length;
    strcpy(pseudo, pseudos[index]);
    printf("Nickname set to \"%s\"\n", pseudo);
}
