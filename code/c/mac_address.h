#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>


int get_mac_address(uint8_t * mac_address, char  * interface);
int is_valid_mac_address(char * mac);
void mac_addr_to_str(uint8_t * mac,char * mac_str);
void str_to_mac_addr(char * str, uint8_t * mac);
