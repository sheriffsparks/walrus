#include "print_helpers.h"

void print_status (char * msg)
{
    printf("\x1B[01;34m[*]\x1B[0m %s\n",msg);
    fflush(stdout);
}

void print_good (char * msg)
{
    printf("\x1B[01;32m[*]\x1B[0m %s\n",msg);
    fflush(stdout);
}

void print_error (char * msg)
{
    fprintf(stderr,"\x1B[01;31m[*]\x1B[0m %s\n",msg);
}

void print_notification (char * msg)
{
	printf("\x1B[01;33m[*]\x1B[0m %s\n",msg);
    fflush(stdout);
}
