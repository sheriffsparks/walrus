#include <stdlib.h>
#include <argp.h>
#include <pthread.h>
#include "80211.h"
#include <sys/time.h>

#include "mac_address.h"
#include "print_helpers.h"

#include <pcap.h>
#define MAX_INTERFACE_LEN 16

static error_t parse_opt(int, char *, struct argp_state *);
void * beacon_thread(void * handle);

uint16_t g_seq_num=0;
/* uint16_t get_seq_num() { */
/*     pthread_mutex_lock(&g_seq_num_lock); */
/*     g_seq_num++; */
/*     pthread_mutex_unlock(&g_seq_num_lock); */
/*     return g_seq_num; */
/* } */
struct arguments {
    uint8_t mac_addr[6];
    char * mac_addr_str;
    char FLAG_MAC_SET;
    char * interface;
};

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
/*TODO: does this need to be global? */
/* pthread_mutex_t g_seq_num_lock = PTHREAD_MUTEX_INITIALIZER; */

int main(int argc, char **argv) {
    /* =========================
     *  SETUP VARS  
     * ========================= 
     */
    /* uint8_t g_mac_addr[6] = {0}; */
    /* char * interface = (char *) malloc(MAX_INTERFACE_LEN); */
    

    /* =========================
     *  ARGUMENT HANDELING
     * ========================= 
     */
    struct argp_option options[] = {
        { "mac-address", 'm', "MACADDRESS", 0,
          "Spoof the mac address of the AP. format-> aa:bb:cc:11:22:33"},
          {0}
    };
    struct arguments g;
    g.FLAG_MAC_SET = 0;
    g.interface = (char *) malloc(MAX_INTERFACE_LEN);
    g.mac_addr_str = (char *) malloc(18);

    struct argp argp = { options, parse_opt, "INTERFACE" };
    argp_parse (&argp, argc, argv, 0, 0, &g);

    /* TODO: Check if interface actually exists */

    if (!g.FLAG_MAC_SET) {
        get_mac_address(g.mac_addr, g.interface);
        mac_addr_to_str(g.mac_addr, g.mac_addr_str);
        printf("%s MAC address assigned from interface default: %s\n", status,
                g.mac_addr_str);
    }

    /* =========================
     *  PCAP HANDLER SETUP
     * ========================= 
     */
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    /* TODO: Figure out what the hell this does */
    pcap_errbuf[0] = '\0';

    pcap_t *handle = pcap_open_live(g.interface, 96, 0, 0, pcap_errbuf);
    if (pcap_errbuf[0] != '\0') {
        print_error(pcap_errbuf);
        return -1;
    }

    struct bpf_program fp;
    char * filter = (char *) malloc(28);
    sprintf(filter, "ether dst %s", g.mac_addr_str);
    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        print_error("Error calling pcap_coompile");
        return -1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        print_error("Error setting filter");
        return -1;
    }

    struct frame_variable *ssid = create_frame_variable(ssid, 0, 4, "wifi");
    const uint8_t ds_data[] = {0x07};
    struct frame_variable *ds = create_frame_variable(ds, 3, 1, &ds_data);
    struct beacon_pkt * beacon = create_beacon(beacon, 2, ssid, ds);
    beacon->hdr->seq_ctrl = 1;
    beacon->b_hdr->timestamp=get_current_timestamp();

    int ret = pcap_sendpacket(handle, beacon->pkt, beacon->size);
    printf("%d", ret);
    /* =========================
     *  CLEAN UP
     * ========================= 
     */
    pcap_close(handle);
    free(filter);
    free(g.interface);
    free(g.mac_addr_str);

    return 0;
}




/* void * beacon_thread(void * args) { */
/*     pcap_t * handle = (pcap_t *) args; */
/*     struct beacon_pkt * beacon = malloc((sizeof(struct beacon_pkt))); */
/*     beacon->size = 0; */
/*     if (create_beacon(&beacon) != 0) { */
/*         print_error("Cannot create beacon"); */
/*     } */
/*     while (1) { */
/*         beacon->hdr->seq_ctrl = (get_seq_num())<<4; */
/*         beacon->b_hdr->timestamp=get_current_timestamp(); */
/*         pcap_sendpacket(handle, beacon->buf, beacon->size); */
/*         usleep(1024*1000); */
/*     } */
/* } */
         

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;
    switch (key) {
        case 'm':
            {
                if (is_valid_mac_address(arg)) {
                    str_to_mac_addr(arg, arguments->mac_addr);
                    mac_addr_to_str(arguments->mac_addr, 
                                    arguments->mac_addr_str);
                    printf("%s MAC address set to %s\n", good, 
                            arguments->mac_addr_str);
                    arguments->FLAG_MAC_SET=1;
                } else {
                    argp_error(state, "Not a valid MAC address");
                }
                break;
            }
        case ARGP_KEY_ARG:
            {
                if (1 <= state->arg_num) {
                    argp_error(state, "Too many arguments");
                } else {
                    strncpy(arguments->interface, arg, MAX_INTERFACE_LEN);
                    printf("%s Interface set to %s\n", status, 
                            arguments->interface);
                }
                
            }
            break;
        case ARGP_KEY_END:
            {
                if ( 1 > state->arg_num) {
                    argp_error(state, "Too few arguments");
                }
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}
