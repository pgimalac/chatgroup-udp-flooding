#ifndef __H_INTERFACE
#define __H_INTERFACE

#include <stdlib.h>

#define PSEUDO_LENGTH 50
#define forbiden " \n\t\r"

#define EFFACER "\e[1;1H\e[2J"
#define RESET "\e[0m\e[0m"
#define CLBEG "\e[1K\e[1G" // clear the line and move to the beginning

#define BLINK "\e[5m"
#define BOLD "\e[1m"
#define DIM "\e[2m"
// reverse foreground and background
#define REV "\e[7m"
#define ITALIC_B "\e[3m"
#define ITALIC_E "\e[23m"
#define HIGHLIGHT_B "\e[7m"
#define HIGHLIGHT_E "\e[27m"
#define UNDERLINE_B "\e[4m"
#define UNDERLINE_E "\e[24m"

/* foregrounds */
#define BLACKf "\e[30m"
#define REDf "\e[31m"
#define GREENf "\e[32m"
#define YELLOWf "\e[33m"
#define BLUEf "\e[34m"
#define MAGENTAf "\e[35m"
#define CYANf "\e[36m"
#define WHITEf "\e[37m"

/* backgrounds */
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
#define COMMAND '/'

void setPseudo(const char *, size_t len);

const char *getPseudo();

void setRandomPseudo();

void handle_command(const char *, size_t len);

void handle_input(char *buffer, size_t buflen);

void print_message(const u_int8_t *, int);

void print_file(u_int8_t type, const u_int8_t *buffer, size_t len);

char **interface_completion(const char *text, int start, int end);

#endif
