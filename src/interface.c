#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <network.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>

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
        fprintf(stderr, "%s%sUsage: %s\n%s", STDERR_F, STDERR_B, usages[0], RESET);
        return;
    }

    rc = add_neighbour(name, service);
    if (rc != 0) {
        fprintf(stderr, "%s%sCould not add the given neighbour: %s\n%s", STDERR_F, STDERR_B, gai_strerror(rc), RESET);
        return;
    }
    printf("%s%s The neighbour %s, %s was added to potential neighbours\n%s", STDOUT_F, STDOUT_B, name, service, RESET);
}

static void name(char *buffer){
    setPseudo(buffer);
}

static void nameRandom(char *buffer){
    setRandomPseudo();
}

static void __print(const neighbour_t *n){
    char ipstr[INET6_ADDRSTRLEN];
    assert (inet_ntop(AF_INET6, &n->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
    printf("%s%s    @ %s / %d\n%s", STDOUT_F, STDOUT_B, ipstr, ntohs(n->addr->sin6_port), RESET);
}

static void print(char *buffer){
    if (hashset_isempty(neighbours)){
        printf("%s%sYou have no neighbour\n%s", STDOUT_F, STDOUT_B, RESET);
    } else {
        printf("%s%sYou have %lu neighbour%s:\n%s", STDOUT_F, STDOUT_B, neighbours->size, neighbours->size == 1 ? "" : "s", RESET);
        hashset_iter(neighbours, __print);
    }
    if (hashset_isempty(potential_neighbours)){
        printf("%s%sYou have no potential_neighbour.\n%s", STDOUT_F, STDOUT_B, RESET);
    } else {
        printf("%s%sYou have %lu potential neighbour%s:\n%s", STDOUT_F, STDOUT_B, potential_neighbours->size,
                    potential_neighbours->size == 1 ? "" : "s", RESET);
        hashset_iter(potential_neighbours, __print);
    }
    printf("%s%s\n%s", STDOUT_F, STDOUT_B, RESET);
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
    printf("Invalid command, possible commands are:\n");
    for (const char **usage = usages; *usage; usage++)
        printf("%s%s    %s\n%s", STDOUT_F, STDOUT_B, *usage, RESET);
}

static void chid(char *buffer) {
    id = random_uint64();
    dprintf(logfd, "New id: %lx.\n", id);
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
    printf("%s%s================================================\n%s", STDOUT_F, STDOUT_B, RESET);
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
    printf("%s%s================================================\n%s", STDOUT_F, STDOUT_B, RESET);
}

// =========== PSEUDO part ===========

const char* getPseudo(){
    return pseudo;
}

void setPseudo(char *buffer){
    buffer += strspn(buffer, forbiden);
    int len = strlen(buffer);
    while (len > 0 && strchr(forbiden, buffer[len - 1]) != NULL)
        len--;

    if (len > PSEUDO_LENGTH){
        fprintf(stderr, "%s%sNickname too long.\n%s", STDERR_F, STDERR_B, RESET);
    } else if (len < 3){
        fprintf(stderr, "%s%sNickname too short\n%s", STDERR_F, STDERR_B, RESET);
    } else {
        for (int i = 0; i < len; i++)
            if (strchr(forbiden, buffer[i]) != NULL)
                buffer[i] = ' ';

        memcpy(pseudo, buffer, len);
        pseudo[len] = '\0';
        printf("%s%sNickname set to \"%s\"\n%s", STDOUT_F, STDOUT_B, pseudo, RESET);
    }
}

void setRandomPseudo(){
    int index = rand() % pseudo_length;
    strcpy(pseudo, pseudos[index]);
    printf("%s%sNickname set to \"%s\"\n%s", STDOUT_F, STDOUT_B, pseudo, RESET);
}
