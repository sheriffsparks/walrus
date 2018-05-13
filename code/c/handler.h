#include <stdint.h>
#include <pcap.h>
#include <stdio.h>
#include "structs.h"

#define WLAN_FC_TYPE_MGMT 0x0000
#define WLAN_FC_SUBTYPE_BEACON 0x0080
#define IEEE80211_STYPE_PROBE_RESP  0x0050
#define IEEE80211_STYPE_AUTH        0x00B0
#define IEEE80211_FCTL_RETRY        0x0800


void pkt_handler(u_char * useless, const struct pcap_pkthdr* pkthdr, 
        const u_char * packet);
int handle_probe_req(const u_char * packet, struct ieee80211_hdr * hdr);
