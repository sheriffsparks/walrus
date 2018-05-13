#include "mac_address.h"

int get_mac_address(uint8_t *  mac_address, char  * interface)
{
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, interface);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
    /*int i;
    for (i = 0; i < 6; ++i)
      printf(" %02x", (unsigned char) s.ifr_addr.sa_data[i]);
      printf("\n");
      printf(" %s\n",s.ifr_addr.sa_data); 
     */
        memcpy(mac_address, s.ifr_addr.sa_data,6);
        return 0;
    }
    
  return 1;
}
void mac_addr_to_str(uint8_t * mac,char * mac_str) {
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}
void str_to_mac_addr(char * str, uint8_t * mac) {
    int values[6];
    sscanf(str, "%x:%x:%x:%x:%x:%x%*c", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5] );
    for(int i=0; i<6; ++i) {
        mac[i]=(uint8_t) values[i];
    }
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}
int is_valid_mac_address(char * mac) {
    int i = 0;
    int s = 0;
    while(*mac){
        if(isxdigit(*mac)) {
            i++;
        }
        else if (*mac == ':') {
            if (i==0 || i/2 -1 !=s)
                break;
            ++s;
        }
        else {
            s=-1;
        }
        ++mac;
    }
    return(i==12 && s==5);
}
