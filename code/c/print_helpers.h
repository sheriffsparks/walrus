#include <stdio.h>

#define good "\x1B[01;32m[*]\x1B[0m"
#define status "\x1B[01;34m[*]\x1B[0m"
#define bad "\x1B[01;31m[*]\x1B[0m"
#define notification "\x1B[01;33m[*]\x1B[0m"

void print_status (char * msg);
void print_good (char * msg);
void print_error (char * msg);
void print_notification (char * msg);
