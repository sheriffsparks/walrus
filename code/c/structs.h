struct beacon_pkt {
    uint8_t * buf;
    uint8_t * rt;
    size_t size;
    struct ieee80211_hdr *hdr;
    struct beacon_hdr *b_hdr;
    struct beacon_variable *rates;
    struct beacon_variable * ssid;
    struct beacon_variable * ds;
    struct beacon_variable * tim;
    struct beacon_variable * erp;
    struct beacon_variable * rsn_hdr;
};

struct probe_resp_pkt {
    uint8_t * buf;
    uint8_t * rt;
    size_t size;
    struct ieee80211_hdr *hdr;
    struct beacon_hdr *p_hdr;
    struct beacon_variable *rates;
    struct beacon_variable * ssid;
    struct beacon_variable * ds;
    struct beacon_variable * erp;
    struct beacon_variable * rsn_hdr;
};

struct ieee80211_hdr {
  uint16_t /*__le16*/ frame_control;
  uint16_t /*__le16*/ duration_id;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  uint16_t /*__le16*/ seq_ctrl;
} __attribute__ ((packed));
/* above line tells gcc to not add any extra space in between struct members */


struct radiotap {
    uint16_t version;
    uint16_t len;
} __attribute__ ((packed));
static const uint8_t u8aRadiotapHeader[] = {

  0x00, 0x00, // <-- radiotap version (ignore this)
  0x12, 0x00, // <-- number of bytes in our header (count the number of "0x"s)

  /**
   * The next field is a bitmap of which options we are including.
   * The full list of which field is which option is in ieee80211_radiotap.h,
   * but I've chosen to include:
   *   0x00 0x01: timestamp
   *   0x00 0x02: flags
   *   0x00 0x03: rate
   *   0x00 0x04: channel
   *   0x80 0x00: tx flags (seems silly to have this AND flags, but oh well)
   */
  //0x0f, 0x80, 0x00, 0x00, original
  0x2e, 0x48, 0x00, 0x00, //removed timestamp

  //0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp

  /**
   * This is the first set of flags, and we've set the bit corresponding to
   * IEEE80211_RADIOTAP_F_FCS, meaning we want the card to add a FCS at the end
   * of our buffer for us.
   */
  0x00,

  0x02, // <-- rate
  0x6c, 0x09, 0xa0, 0x00, // <-- channel
  0xcd, // signal strength
  0x00, //antenna
  0x00, 0x00 //rx flags

  /**
   * This is the second set of flags, specifically related to transmissions. The
   * bit we've set is IEEE80211_RADIOTAP_F_TX_NOACK, which means the card won't
   * wait for an ACK for this frame, and that it won't retry if it doesn't get
   * one.
   */
  //0x08, 0x00,
};

struct beacon_hdr {
	uint64_t timestamp;
    uint16_t interval;
    uint16_t capability_info;
}__attribute__ ((packed));

struct beacon_variable {
    uint8_t id;
    uint8_t len;
    uint8_t buf[1];
}__attribute__ ((packed));
