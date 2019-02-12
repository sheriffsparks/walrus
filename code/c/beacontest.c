#include <stdio.h>
#include <sys/time.h>
#include "80211.h"

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

int main(int argc, char **argv) {
    struct frame_variable *ssid = create_frame_variable(ssid, 0, 4, "wifi");
    const uint8_t ds_data[] = {0x07};
    struct frame_variable *ds = create_frame_variable(ds, 3, 1, &ds_data);
    struct beacon_pkt * beacon = create_beacon(beacon, 2, ssid, ds);
    beacon->hdr->seq_ctrl = 1;
    beacon->b_hdr->timestamp=get_current_timestamp();
}
