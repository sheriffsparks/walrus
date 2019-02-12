#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#define RADIOTAP_LEN 18
#define MAC_LEN 6
static const uint8_t BROADCAST_MAC[6]= {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static const uint8_t radioTapHeader[] = {
    0x00, 0x00,
    0x12, 0x00,
    0x2e, 0x48, 0x00, 0x00,
    0x00,
    0x02,
    0x6c, 0x09, 0xa0, 0x00,
    0xcd,
    0x00,
    0x00, 0x00
};

struct i80211_hdr {
    /* Defines the basic 80211 header, may need to edit this for cases where 4
     * addresses are needed
     */
    uint16_t frame_ctrl;
    uint16_t duration_id;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
}__attribute__((packed));

struct frame_variable {
    /* Defines a a simple TLV structure that is used accross control frame 
     * messages.
     */
    uint8_t id;
    uint8_t len;
    uint8_t buf[];
}__attribute__((packed));

struct beacon_hdr {
    uint64_t timestamp;
    uint16_t interval;
    uint16_t capability_info;
}__attribute__((packed));

struct beacon_pkt {
    size_t size;
    struct i80211_hdr *hdr;
    struct beacon_hdr *b_hdr;
    uint8_t *pkt;
};

struct frame_variable * create_frame_variable(
        struct frame_variable * v, uint8_t id, uint8_t len, const void * buf)
{
    v = malloc(sizeof(*v) + len); 
    v->id = id;
    v->len = len;
    memcpy(v->buf, buf, len);
    return v;
}

struct beacon_pkt * create_beacon(struct beacon_pkt *b, int num_arg, ...) {
    b = malloc(sizeof(*b));

    va_list variable_params;
    va_start(variable_params, num_arg);
    size_t param_size = 0;
    struct frame_variable *params[num_arg];
    for (int i = 0; i < num_arg; i++) {
        struct frame_variable *cur = va_arg(variable_params, 
                                            struct frame_variable *);
        param_size += cur->len + sizeof(struct frame_variable);
        params[i] = cur;
    }
    b->size = RADIOTAP_LEN
                 + sizeof(struct i80211_hdr)
                 + sizeof(struct beacon_hdr)
                 + param_size;

    b->pkt = malloc(b->size);
    uint8_t *cur = b->pkt;
    memcpy(cur, radioTapHeader, RADIOTAP_LEN);
    cur+=RADIOTAP_LEN;

    b->hdr = (struct i80211_hdr *) cur;
    b->hdr->duration_id=0xffff;
    memcpy(b->hdr->addr1, BROADCAST_MAC, MAC_LEN);
    memcpy(b->hdr->addr2, BROADCAST_MAC, MAC_LEN);
    memcpy(b->hdr->addr3, BROADCAST_MAC, MAC_LEN);
    cur += sizeof(struct i80211_hdr);

    b->b_hdr = (struct beacon_hdr *) cur;
    b->b_hdr->interval = 0x0064;
    b->b_hdr->capability_info = 0x0431;
    cur += sizeof(struct beacon_hdr);

    for (int i = 0; i < num_arg; i++) {
        memcpy(cur, params[i], params[i]->len + sizeof(struct frame_variable));
        cur += params[i]->len + sizeof(struct frame_variable);
    }

    va_end(variable_params);
    return b;
}
