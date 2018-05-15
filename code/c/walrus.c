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
const uint8_t g_rates[10]= {0x02, 0x04, 0x0b, 0x0c, 0x12, 0x16};
const int g_rates_len=6*sizeof(uint8_t);
const uint8_t broadcast_mac[6]= { 0xff, 0xff, 0xff, 0xff, 0xff,0xff};
const char * g_ssid = "WHY";
char FLAG_MAC_SET=0;
pthread_mutex_t g_seq_num_lock = PTHREAD_MUTEX_INITIALIZER;

/* Function Prototypes */
void get_pcap_error(pcap_t *);
int send_beacon(pcap_t * handle);
void * beacon_thread(void * handle);
void extend_buffer(uint8_t * buf, int size);
void pkt_handler(u_char * useless, const struct pcap_pkthdr* pkthdr, 
        const u_char * packet);
int create_probe_response(struct probe_resp_pkt ** probe_resp, const u_char * packet, struct ieee80211_hdr *req_hdr);
uint64_t get_current_timestamp();
int add_beacon_variable(uint8_t ** buf,size_t * size, struct beacon_variable * b_var, const uint8_t id, const uint8_t len,const uint8_t data[]);
int create_beacon(struct beacon_pkt ** beacon);
int create_authentication_request(struct authentication_pkt * g_auth);

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


    struct authentication_pkt * g_auth=malloc(sizeof(struct authentication_pkt));

    struct handler_data * h_data=malloc(sizeof(struct handler_data));
    h_data->handle=handle;
    h_data->auth=g_auth;

    create_authentication_request(h_data->auth);

    if(pcap_setfilter(handle,&fp) == -1) { 
        print_error("Error setting filter");
        return -1;
    }
    pcap_loop(handle,-1,pkt_handler,(u_char *) h_data);
    sleep(100);
    
	pcap_close(handle);
    free(g_interface);
    return 0;
}

void * beacon_thread(void * args) {
    pcap_t * handle= (pcap_t *) args;
    printf("handle: %p\n", handle);
    struct beacon_pkt * beacon=malloc((sizeof(struct beacon_pkt)));
    beacon->size=0;
    if(create_beacon(&beacon)!=0) {
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

int create_beacon(struct beacon_pkt ** beacon)
{
	uint8_t fcchunk[2];
    uint8_t * buf=(*beacon)->buf;
    size_t size=(*beacon)->size;

	size = sizeof(u8aRadiotapHeader) 
        + sizeof(struct ieee80211_hdr) 
        + sizeof(struct beacon_hdr) 
        + (sizeof(struct beacon_variable) 
        + strlen(g_ssid)-1) 
        + (sizeof(struct beacon_variable) 
        + g_rates_len-1);

	buf = (uint8_t *) malloc(size);
    (*beacon)->buf=buf;
	(*beacon)->rt = (uint8_t *) buf;
	(*beacon)->hdr = (struct ieee80211_hdr *) (buf + sizeof(u8aRadiotapHeader));
    (*beacon)->b_hdr = (struct beacon_hdr *) ((*beacon)->hdr+1);
    (*beacon)->ssid = (struct beacon_variable *) ((*beacon)->b_hdr+1);
    (*beacon)->rates= (struct beacon_variable *) ((*beacon)->ssid->buf+strlen(g_ssid));
    

    /* RADIOTAPHEADER */
	memcpy((*beacon)->rt, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));
	fcchunk[0]=WLAN_FC_SUBTYPE_BEACON;
	fcchunk[1]=0x00;
	memcpy(&(*beacon)->hdr->frame_control, &fcchunk[0], 2*sizeof(uint8_t));

    /* IEEE80211 HEADER*/
	(*beacon)->hdr->duration_id=0xffff;
    (*beacon)->hdr->seq_ctrl=(get_seq_num())<<4;
	memcpy(&(*beacon)->hdr->addr1[0],broadcast_mac,6*sizeof(uint8_t));
	memcpy(&(*beacon)->hdr->addr2[0],g_mac_addr,6*sizeof(uint8_t));
	memcpy(&(*beacon)->hdr->addr3[0],g_mac_addr,6*sizeof(uint8_t));

    (*beacon)->b_hdr->timestamp=get_current_timestamp();
    (*beacon)->b_hdr->interval=0x0064;
    (*beacon)->b_hdr->capability_info=0x0431;

    /* SSID */
    (*beacon)->ssid->id=0x00;
    (*beacon)->ssid->len=strlen(g_ssid);
    memcpy((*beacon)->ssid->buf, g_ssid,strlen(g_ssid));

    /* SUPPORTED RATES */
    (*beacon)->rates->id=0x01;
    (*beacon)->rates->len=g_rates_len;
    memcpy((*beacon)->rates->buf, g_rates,g_rates_len);
    
    /* DS PARAMETERS */
    const uint8_t ds_data[]={0x07};
    if(add_beacon_variable(&buf, &size, (*beacon)->ds, 0x03, 0x01, ds_data) != 0) {
        return -1;
    }

    /* TIM */
    const uint8_t tim_data[]= { 0x00, 0x01,0x00, 0x00 };
    if(add_beacon_variable(&buf, &size, (*beacon)->tim, 0x05, 0x04, tim_data) != 0) {
        return -1;
    }

    ///* ERP */
    const uint8_t erp_data[]={0x00};
    if(add_beacon_variable(&buf, &size, (*beacon)->ext_capes, 0x2a, 0x01, erp_data) != 0) {
        return -1;
    }

    /* RSN */
    struct rsn_data {
        uint16_t version;
        uint32_t group_cipher;
        uint16_t pairwise_count;
        uint32_t pairwise_list;
        uint16_t auth_key_count;
        uint32_t auth_key_list;
        uint16_t rsn_caps;
    }__attribute__ ((packed));

    struct rsn_data * rsn =malloc(sizeof(struct rsn_data));
    if(!rsn) {
        print_error("Unable to create memory for RSN");
        return -1;
    }
    rsn->version=0x00001;
    rsn->group_cipher=0x04ac0f00;
    rsn->pairwise_count=0x0001;
    rsn->pairwise_list=0x04ac0f00;
    rsn->auth_key_count=0x0001;
    rsn->auth_key_list=0x01ac0f00;
    rsn->rsn_caps=0x0000;

    if(add_beacon_variable(&buf, &size, (*beacon)->rsn_hdr, 0x30, 0x14,(uint8_t *) rsn) != 0) {
        return -1;
    }
    free(rsn);

    /* EXTENDED CAPABILITIES */
    const uint8_t ext_capes_data[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    if(add_beacon_variable(&buf, &size, (*beacon)->ext_capes, 0x7f, 0x08, ext_capes_data) != 0) {
        return -1;
    }

    /* Forced to reassign these becuase realloc could change location
     * If I want to use any other of the headers outside of this function I will have to do the same
     * This is probably really bad coding practice. Since the overall size of the beacon pkt is known at compile time, I should just be making one malloc. However I could not come up with a concise way of doing this and the current way allows me to add my variable parameters quickly
     */
    (*beacon)->buf=buf;
    (*beacon)->size=size;
    (*beacon)->hdr=(struct ieee80211_hdr *) (buf+sizeof(u8aRadiotapHeader));
    (*beacon)->b_hdr=(struct beacon_hdr *) (((*beacon)->hdr) + sizeof(struct ieee80211_hdr));
    return 0;
}

int add_beacon_variable(uint8_t ** buf,size_t * size, struct beacon_variable * b_var, const uint8_t id, const uint8_t len,const uint8_t data[]) {
    size_t oldsize;
    oldsize=*size;
    *size=*size+sizeof(struct beacon_variable)+(sizeof(uint8_t))*(len-1);
    *buf=realloc(*buf,*size);
    if(!*buf) {
        print_error("unable to extend buf");
        return -1;
    }
    b_var=(struct beacon_variable *) (*buf+oldsize);
    b_var->id=id;
    b_var->len=len;
    memcpy(&b_var->buf, data, len);
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

void pkt_handler(u_char * passed_data, const struct pcap_pkthdr* pkthdr, 
        const u_char * packet) {

    const u_char * rt_hdr;
    //pcap_t * handle= (pcap_t *) useless;
    struct handler_data * h_data = (struct handler_data *)(passed_data);
    pcap_t * handle=h_data->handle;

    rt_hdr=packet;
    struct radiotap * rt=(struct radiotap *) rt_hdr;

    const u_char * hdr_ptr;
    hdr_ptr=packet+rt->len;
    struct ieee80211_hdr * hdr=(struct ieee80211_hdr *) hdr_ptr;
    char src_mac[18];
    mac_addr_to_str(hdr->addr2, src_mac);
    /* For now we don't care about retransmits below clears retry bit */
    //hdr->frame_control=hdr->frame_control & ~IEEE80211_FCTL_RETRY;
    if(hdr->frame_control==IEEE80211_STYPE_AUTH ) {
	    memcpy(&h_data->auth->hdr->addr1[0], hdr->addr2,6*sizeof(uint8_t));
        //handle_authentication_request(hdr, handle);
        if(pcap_sendpacket(handle, h_data->auth->buf, h_data->auth->size) !=0)
        {
           get_pcap_error(handle);
        }
            printf("%s Sent Authentication Response to %s\n", notification, src_mac);
    }
    if(hdr->frame_control==IEEE80211_STYPE_PROBE_REQ) {
        handle_probe_req(packet,hdr, handle);
        printf("%s Sent Probe Response to %s\n", notification, src_mac);
    }
}
int create_authentication_request(struct authentication_pkt * g_auth)
{
	uint8_t fcchunk[2];

	g_auth->size = sizeof(u8aRadiotapHeader) 
        + sizeof(struct ieee80211_hdr) 
        + sizeof(struct authentication_data);

	g_auth->buf = (uint8_t *) malloc(g_auth->size);
	g_auth->rt = (uint8_t *) g_auth->buf;
	g_auth->hdr = (struct ieee80211_hdr *) (g_auth->buf + sizeof(u8aRadiotapHeader));
    g_auth->auth = (struct authentication_data *) (g_auth->hdr + 1);

    /* RADIOTAPHEADER */
	memcpy(g_auth->rt, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));
	fcchunk[0]=IEEE80211_STYPE_AUTH;
	fcchunk[1]=0x00;
	memcpy(&g_auth->hdr->frame_control, &fcchunk[0], 2*sizeof(uint8_t));

    /* IEEE80211 HEADER*/
	g_auth->hdr->duration_id=0xffff;
    g_auth->hdr->seq_ctrl=(get_seq_num())<<4;
	memcpy(&g_auth->hdr->addr1[0], broadcast_mac,6*sizeof(uint8_t));
	memcpy(&g_auth->hdr->addr2[0],g_mac_addr,6*sizeof(uint8_t));
	memcpy(&g_auth->hdr->addr3[0],g_mac_addr,6*sizeof(uint8_t));

    /* AUTHENTICATION VALUES */
    g_auth->auth->algorithm=0x0000;
    g_auth->auth->seq=0x0002;
    g_auth->auth->status_code=0x0000;

    return 0;
}


int handle_probe_req(const u_char * packet, struct ieee80211_hdr * hdr, pcap_t * handle) {
    /* Get source mac address
     * get supported rates
     * find common lowest rate
     */
    struct probe_resp_pkt * probe_resp=malloc(sizeof(struct probe_resp_pkt));

    if(create_probe_response(&probe_resp, packet, hdr)!=0){
        print_error("Unable to create probe_response");
        return -1;
    }

    if(pcap_sendpacket(handle, probe_resp->buf, probe_resp->size) !=0)
    {
       get_pcap_error(handle);
       return -1;
    }
    free(probe_resp);

    return 0;
}

int create_probe_response(struct probe_resp_pkt ** probe_resp, const u_char *packet, struct ieee80211_hdr * req_hdr)
{
	uint8_t fcchunk[2];
    uint8_t * buf=(*probe_resp)->buf;
    size_t size=(*probe_resp)->size;

	size = sizeof(u8aRadiotapHeader) 
        + sizeof(struct ieee80211_hdr) 
        + sizeof(struct beacon_hdr) 
        + (sizeof(struct beacon_variable) 
        + strlen(g_ssid)-1) 
        + (sizeof(struct beacon_variable) 
        + g_rates_len-1);

	buf = (uint8_t *) malloc(size);
    (*probe_resp)->buf=buf;
	(*probe_resp)->rt = (uint8_t *) buf;
	(*probe_resp)->hdr = (struct ieee80211_hdr *) (buf + sizeof(u8aRadiotapHeader));
    (*probe_resp)->p_hdr = (struct beacon_hdr *) ((*probe_resp)->hdr+1);
    (*probe_resp)->ssid = (struct beacon_variable *) ((*probe_resp)->p_hdr+1);
    (*probe_resp)->rates= (struct beacon_variable *) ((*probe_resp)->ssid->buf+strlen(g_ssid));
    

    /* RADIOTAPHEADER */
	memcpy((*probe_resp)->rt, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));
	fcchunk[0]=IEEE80211_STYPE_PROBE_RESP;
	fcchunk[1]=0x00;
	memcpy(&(*probe_resp)->hdr->frame_control, &fcchunk[0], 2*sizeof(uint8_t));

    /* IEEE80211 HEADER*/
	(*probe_resp)->hdr->duration_id=0xffff;
    (*probe_resp)->hdr->seq_ctrl=(get_seq_num())<<4;
	memcpy(&(*probe_resp)->hdr->addr1[0], req_hdr->addr2,6*sizeof(uint8_t));
	memcpy(&(*probe_resp)->hdr->addr2[0],g_mac_addr,6*sizeof(uint8_t));
	memcpy(&(*probe_resp)->hdr->addr3[0],g_mac_addr,6*sizeof(uint8_t));

    (*probe_resp)->p_hdr->timestamp=get_current_timestamp();
    (*probe_resp)->p_hdr->interval=0x0064;
    (*probe_resp)->p_hdr->capability_info=0x0431;

    /* SSID */
    (*probe_resp)->ssid->id=0x00;
    (*probe_resp)->ssid->len=strlen(g_ssid);
    memcpy((*probe_resp)->ssid->buf, g_ssid,strlen(g_ssid));

    /* SUPPORTED RATES */
    (*probe_resp)->rates->id=0x01;
    (*probe_resp)->rates->len=g_rates_len;
    memcpy((*probe_resp)->rates->buf, g_rates,g_rates_len);
    
    /* DS PARAMETERS */
    const uint8_t ds_data[]={0x07};
    if(add_beacon_variable(&buf, &size, (*probe_resp)->ds, 0x03, 0x01, ds_data) != 0) {
        return -1;
    }

    ///* ERP */
    const uint8_t erp_data[]={0x00};
    if(add_beacon_variable(&buf, &size, (*probe_resp)->ext_capes, 0x2a, 0x01, erp_data) != 0) {
        return -1;
    }

    /* RSN */
    struct rsn_data {
        uint16_t version;
        uint32_t group_cipher;
        uint16_t pairwise_count;
        uint32_t pairwise_list;
        uint16_t auth_key_count;
        uint32_t auth_key_list;
        uint16_t rsn_caps;
    }__attribute__ ((packed));

    struct rsn_data * rsn =malloc(sizeof(struct rsn_data));
    if(!rsn) {
        print_error("Unable to create memory for RSN");
        return -1;
    }
    rsn->version=0x00001;
    rsn->group_cipher=0x04ac0f00;
    rsn->pairwise_count=0x0001;
    rsn->pairwise_list=0x04ac0f00;
    rsn->auth_key_count=0x0001;
    rsn->auth_key_list=0x01ac0f00;
    rsn->rsn_caps=0x0000;

    if(add_beacon_variable(&buf, &size, (*probe_resp)->rsn_hdr, 0x30, 0x14,(uint8_t *) rsn) != 0) {
        return -1;
    }
    free(rsn);

    /* EXTENDED CAPABILITIES */
    const uint8_t ext_capes_data[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    if(add_beacon_variable(&buf, &size, (*probe_resp)->ext_capes, 0x7f, 0x08, ext_capes_data) != 0) {
        return -1;
    }

    /* Forced to reassign these becuase realloc could change location
     * If I want to use any other of the headers outside of this function I will have to do the same
     * This is probably really bad coding practice. Since the overall size of the beacon pkt is known at compile time, I should just be making one malloc. However I could not come up with a concise way of doing this and the current way allows me to add my variable parameters quickly
     */
    (*probe_resp)->buf=buf;
    (*probe_resp)->size=size;
    (*probe_resp)->hdr=(struct ieee80211_hdr *) (buf+sizeof(u8aRadiotapHeader));
    (*probe_resp)->p_hdr=(struct beacon_hdr *) (((*probe_resp)->hdr) + sizeof(struct ieee80211_hdr));
    return 0;
}
