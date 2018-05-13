#include "handler.h"
#include <stdlib.h>
#include "print_helpers.h"
#include "mac_address.h"

void pkt_handler(u_char * useless, const struct pcap_pkthdr* pkthdr, 
        const u_char * packet) {

    const u_char * rt_hdr;
    rt_hdr=packet;
    struct radiotap * rt=(struct radiotap *) rt_hdr;
    printf("Radio Tap header length: %d\n", rt->len);

    const u_char * hdr_ptr;
    hdr_ptr=packet+rt->len;
    struct ieee80211_hdr * hdr=(struct ieee80211_hdr *) hdr_ptr;
    /* For now we don't care about retransmits below clears retry bit */
    hdr->frame_control=hdr->frame_control & ~IEEE80211_FCTL_RETRY;
    char src_mac[18];
    mac_addr_to_str(hdr->addr2, src_mac);
    printf("%s Recieved packet from %s\n", notification, src_mac);
    if(hdr->frame_control==IEEE80211_STYPE_AUTH ) {
        printf("Got Authentication Frame\n");
    }
    if(hdr->frame_control==IEEE80211_STYPE_PROBE_RESP) {
        print_status("Got Probe Request");
        handle_probe_req(packet,hdr);
    }
}

int handle_probe_req(const u_char * packet, struct ieee80211_hdr * hdr) {
    /* Get source mac address
     * get supported rates
     * find common lowest rate
     */
    return 0;
}

