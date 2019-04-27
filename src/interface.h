#ifndef __H_INTERFACE
#define __H_INTERFACE

#define PSEUDO_LENGTH 50
#define forbiden " \n\t\r"

void setPseudo(char*);

char* getPseudo();

void setRandomPseudo();

void handle_command(char*);

#endif
