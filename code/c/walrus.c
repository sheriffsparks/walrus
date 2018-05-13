#include <stdlib.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <argp.h>
#include "print_helpers.h"
#include "mac_address.h"
#include "handler.h"

#define MAX_INTERFACE_LEN 16


/* GLOBALS */
uint8_t g_mac_addr[6]={0};
char g_mac_addr_str[17];
char * g_interface;
uint16_t g_seq_num=0;
const uint8_t g_rates[10]= {0x01, 0x08, 0x06, 0x09, 0x0c, 0x12, 0x18, 
                                0x24, 0x30, 0x36};
const int g_rates_len=10*sizeof(uint8_t);
const uint8_t broadcast_mac[6]= { 0xff, 0xff, 0xff, 0xff, 0xff,0xff};
const char * g_ssid = "DABBCC";
char FLAG_MAC_SET=0;
pthread_mutex_t g_seq_num_lock = PTHREAD_MUTEX_INITIALIZER;

/* Function Prototypes */
void get_pcap_error(pcap_t *);
int send_beacon(pcap_t * handle);
void * beacon_thread(void * handle);
void extend_buffer(uint8_t * buf, int size);
void pkt_handler(u_char * useless, const struct pcap_pkthdr* pkthdr, 
        const u_char * packet);
int create_probe_response(struct probe_resp_pkt * probe_resp);
uint64_t get_current_timestamp();

int create_beacon(struct beacon_pkt * beacon);
uint16_t get_seq_num()
{
    pthread_mutex_lock(&g_seq_num_lock);
    g_seq_num++;
    pthread_mutex_unlock(&g_seq_num_lock);
    return g_seq_num;
}



static int parse_opt(int key, char * arg, struct argp_state *state) {
    int * arg_count = state->input;
    switch(key) {
        case 'm': 
            {
                if(is_valid_mac_address(arg)){
                    str_to_mac_addr(arg,g_mac_addr);
                    mac_addr_to_str(g_mac_addr, g_mac_addr_str);
                    printf("%s Mac address set to %s\n", good, g_mac_addr_str);
                    FLAG_MAC_SET=1;
                }
                else {
                    argp_error(state, "Not a valid MAC Address");
                }
                break;
            }
        case ARGP_KEY_ARG:
            {
                (*arg_count)--;
                if(*arg_count>=0) {
                    if(arg==NULL)
                    {
                        argp_failure(state, 1 , 0, "interface not supplied");
                    }
                    g_interface=(char *) malloc(strlen(arg));
                    strncpy(g_interface, arg, MAX_INTERFACE_LEN);
                    printf("%s Interface set to %s\n", status, g_interface);
                }
            }
            break;
        case ARGP_KEY_END:
            {
                if(*arg_count >= 1) 
                    argp_error(state, "too few arguments");
                else if(*arg_count <0)
                    argp_error(state,"too many arguments");
            }
            break;
    }
    return 0;
}

int main(int argc, char **argv) {
    /* ARGUMENT HANDELING */
    struct argp_option options[]= {
        { "mac-addres", 'm', "MACADDRESS", 0, "Spoof the mac address of AP. format-> aa:bb:cc:11:22:33"},
        { 0 }
    };
    int arg_count =1;
    struct argp argp={ options, parse_opt, "INTERFACE" };
    argp_parse (&argp, argc, argv, 0,0,&arg_count);

    /* CREATE PCAP HANDLE */
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0]='\0';

    if(!FLAG_MAC_SET) {
        get_mac_address(g_mac_addr,g_interface);

        mac_addr_to_str(g_mac_addr,g_mac_addr_str);
        printf("%s MAC address assigned from interface default: %s\n", status, g_mac_addr_str);
    }
    
    pcap_t* handle=pcap_open_live(g_interface,96,0,0,pcap_errbuf);
    if (pcap_errbuf[0]!='\0') {
        print_error(pcap_errbuf);
        return -1;
    }
    printf("handle: %p\n", handle);
    pthread_t tid;
    if(pthread_create(&tid, NULL, beacon_thread,(void *) handle)!=0) {
        print_error("Unable to create Beacon Thread");
        return -1;
    }
    struct bpf_program fp;
    /* TODO: update below to dynamically update mac */
    char * filter=(char *) malloc(28);
    sprintf(filter,"ether dst %s", g_mac_addr_str);
    if(pcap_compile(handle,&fp,filter,0,PCAP_NETMASK_UNKNOWN) == -1) { 
        print_error("Error calling pcap_compile"); 
        return -1; 
    }
    if(pcap_setfilter(handle,&fp) == -1) { 
        print_error("Error setting filter");
        return -1;
    }
    pcap_loop(handle,-1,pkt_handler,NULL);
    sleep(100);

	pcap_close(handle);
    free(g_interface);
    return 0;
}

void * beacon_thread(void * args) {
    pcap_t * handle= (pcap_t *) args;
    printf("handle: %p\n", handle);
    struct beacon_pkt * beacon=(struct beacon_pkt *) malloc((sizeof(struct beacon_pkt)));
    beacon->size=0;
    if(create_beacon(beacon)!=0) {
        print_error("Cannot create beacon");
    }
    while(1) {
        beacon->hdr->seq_ctrl=(get_seq_num())<<4;
        beacon->b_hdr->timestamp=get_current_timestamp();
        pcap_sendpacket(handle, beacon->buf, beacon->size);
        /* usleep might be depricated? */
        usleep(1024*100);
    }
}

int create_probe_response(struct probe_resp_pkt * probe_resp)
{
    return 0;
}

int create_beacon(struct beacon_pkt * beacon)
{
	uint8_t fcchunk[2];
    uint8_t * buf=beacon->buf;
    size_t size=beacon->size;

	size = sizeof(u8aRadiotapHeader) + sizeof(struct ieee80211_hdr) 
        + sizeof(struct beacon_hdr) + (sizeof(struct beacon_variable) 
        + strlen(g_ssid)-1) + (sizeof(struct beacon_variable) + g_rates_len-1);

    /* DEBUG */
    //printf("size of uint8_t:  %d\n",sizeof(uint8_t));
    //printf("size of uint16_t:  %d\n",sizeof(uint16_t));
    //printf("size of ieee80211_hdr:  %d\n",sizeof(struct ieee80211_hdr));
    //printf("size of beacon_hdr:  %d\n",sizeof(struct beacon_hdr));
    //printf("size of beacon_variable: %d\n",sizeof(struct beacon_variable));
    /* DEBUG */

	buf = (uint8_t *) malloc(size);
    beacon->buf=buf;
	beacon->rt = (uint8_t *) buf;
	beacon->hdr = (struct ieee80211_hdr *) (buf + sizeof(u8aRadiotapHeader));
    beacon->b_hdr = (struct beacon_hdr *) (beacon->hdr+1);
    beacon->ssid = (struct beacon_variable *) (beacon->b_hdr+1);
    beacon->rates= (struct beacon_variable *) (beacon->ssid->buf+strlen(g_ssid));
    

    /* RADIOTAPHEADER */
	memcpy(beacon->rt, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));
	fcchunk[0]=WLAN_FC_SUBTYPE_BEACON;
	fcchunk[1]=0x00;
	memcpy(&beacon->hdr->frame_control, &fcchunk[0], 2*sizeof(uint8_t));

    /* IEEE80211 HEADER*/
	beacon->hdr->duration_id=0xffff;
    beacon->hdr->seq_ctrl=(get_seq_num())<<4;
	memcpy(&beacon->hdr->addr1[0],broadcast_mac,6*sizeof(uint8_t));
	memcpy(&beacon->hdr->addr2[0],g_mac_addr,6*sizeof(uint8_t));
	memcpy(&beacon->hdr->addr3[0],g_mac_addr,6*sizeof(uint8_t));

    beacon->b_hdr->timestamp=get_current_timestamp();
    beacon->b_hdr->interval=0x0064;
    beacon->b_hdr->capability_info=0x0431;

    /* SSID */
    beacon->ssid->id=0x00;
    beacon->ssid->len=strlen(g_ssid);
    memcpy(beacon->ssid->buf, g_ssid,strlen(g_ssid));

    /* SUPPORTED RATES */
    beacon->rates->id=0x01;
    beacon->rates->len=0x0a;
    memcpy(beacon->rates->buf, g_rates,10*sizeof(uint8_t));
    
    ///* INTERWORKING */
    //struct beacon_variable * interworking;
    //buf=realloc(buf, size+sizeof(struct beacon_variable));
    //if(!buf) {
    //    fprintf(stderr, "unable to extend buf\n");
    //    return -1;
    //}
    //interworking=(struct beacon_variable *)(buf+size);
    //size=size+sizeof(struct beacon_variable);
    //interworking->id=0x6b;
    //interworking->len=0x01;
    //interworking->buf[0]=0x12;
    
    /* DS PARAMETER SET */
    buf=realloc(buf, size+sizeof(struct beacon_variable));
    if(!buf) {
        fprintf(stderr, "unable to exetend buffer\n");
        return -1;
    }
    beacon->ds=(struct beacon_variable *)(buf+size);
    size=size+sizeof(struct beacon_variable);
    beacon->ds->id=0x03;
    beacon->ds->len=0x01;
    beacon->ds->buf[0]=0x07;

    /* TIM */
    buf=realloc(buf, size+sizeof(struct beacon_variable)+(4-1));
    if(!buf) {
        fprintf(stderr, "unable to extend buf\n");
        return -1;
    }

    beacon->tim = (struct beacon_variable *)(buf+size);
    size=size+sizeof(struct beacon_variable)+(4-1);

    beacon->tim->id=0x05;
    beacon->tim->len=0x04;
    uint8_t tim_data[]= { 0x00, 0x01,0x00, 0x00 };
    memcpy(&beacon->tim->buf,tim_data,beacon->tim->len); 

    ///* ERP */
    int oldsize=size;
    size=size+sizeof(struct beacon_variable);
    buf=realloc(buf, size);
    if(!buf) {
        fprintf(stderr, "unable to extend buf\n");
        return -1;
    }
    beacon->erp=(struct beacon_variable *) (buf+oldsize);
    beacon->erp->id=0x2a;
    beacon->erp->len=0x01;
    beacon->erp->buf[0]=0x00;

    /* RSN */
    struct rsn_data {
        uint32_t group_cipher;
        uint16_t pairwise_count;
        uint32_t pairwise_list;
        uint16_t auth_key_count;
        uint32_t auth_key_list;
        uint16_t rsn_caps;
    }__attribute__ ((packed));
    oldsize=size;
    size=size+sizeof(struct beacon_variable)+1;
    buf=realloc(buf,size);
    if(!buf) {
        fprintf(stderr, "unable to extend buf\n");
        return -1;
    }
    beacon->rsn_hdr=(struct beacon_variable *) (buf+oldsize);
    beacon->rsn_hdr->id=0x30;
    beacon->rsn_hdr->len=0x14;
    // RSN Version
    beacon->rsn_hdr->buf[0]=0x01;
    beacon->rsn_hdr->buf[1]=0x00;

    struct rsn_data * rsn;
    oldsize=size;
    size=size+sizeof(struct rsn_data);
    buf=realloc(buf,size);
    rsn=(struct rsn_data *) (buf+oldsize);

    rsn->group_cipher=0x04ac0f00;
    rsn->pairwise_count=0x0001;
    rsn->pairwise_list=0x04ac0f00;
    rsn->auth_key_count=0x0001;
    rsn->auth_key_list=0x01ac0f00;
    rsn->rsn_caps=0x0000;

    beacon->size=size;
    beacon->buf=buf;
    return 0;
}

void get_pcap_error(pcap_t * handle)
{
    fprintf(stderr,"pcap: %s\n", pcap_geterr(handle));
}

uint64_t get_current_timestamp()
{
	struct timeval t;
	
	int code = gettimeofday( &t, NULL );
	if ( code != 0 )
	{
		perror( "error calling gettimeofday" );
	}
	// Convert seconds to microseconds
	// For the purposes of 802.11 timestamps, we don't care about what happens
	// when this value wraps. As long as the value wraps consistently, we are
	// happy
	uint64_t timestamp = t.tv_sec * 1000000LL;
	timestamp += t.tv_usec;
	
	return timestamp;
}
