#ifndef __H_INTERFACE
#define __H_INTERFACE

#include <stdlib.h>

#define PSEUDO_LENGTH 50
#define forbiden " \n\t\r"

#define EFFACER "\e[1;1H\e[2J"
#define RESET "\e[0m\e[0m"

#define BLACKf "\e[30m"
#define REDf "\e[31m"
#define GREENf "\e[32m"
#define YELLOWf "\e[33m"
#define BLUEf "\e[34m"
#define MAGENTAf "\e[35m"
#define CYANf "\e[36m"
#define WHITEf "\e[37m"

#define BLACKb "\e[40m"
#define REDb "\e[41m"
#define GREENb "\e[42m"
#define YELLOWb "\e[43m"
#define BLUEb "\e[44m"
#define MAGENTAb "\e[45m"
#define CYANb "\e[46m"
#define WHITEb "\e[47m"

#define LOGFD_F YELLOWf
#define LOGFD_B ""

#define STDERR_F REDf
#define STDERR_B ""

#define STDOUT_F WHITEf
#define STDOUT_B ""

#define SEPARATOR "===============================================\n"

void setPseudo(char*);

const char* getPseudo();

void setRandomPseudo();

void handle_command(char*);

void print_message(const u_int8_t*, int);

#endif
