#include <string.h>
#include <stdlib.h>

#include "pseudo.h"

#define PSEUDO_LENGTH 50

char pseudo[PSEUDO_LENGTH + 1];

const int pseudo_length = 19;
const char *pseudos[19] = {
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
                "Sherlock"
};

char* getPseudo(){
    return pseudo;
}

void setPseudo(char *new, int size){
    if (size > PSEUDO_LENGTH) size = PSEUDO_LENGTH;
    strncpy(pseudo, new, size);
}

void setRandomPseudo(){
    int index = rand() % pseudo_length;
    memcpy(pseudo, pseudos[index], strlen(pseudos[index]));
}
