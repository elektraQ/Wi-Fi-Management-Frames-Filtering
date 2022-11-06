# Author:    Nirmal Selvarathinam
# Created:   18.06.2021

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse

beaconCount = 0
probeReqCount = 0
probeRespCount = 0
deauthCount = 0
disassCount = 0
otherMgmtFrames = 0
others = 0

def packet_callback(packet):
    if packet.haslayer(Dot11):
        if(packet.type == 0): # filtering all management frames
            if(packet.subtype == 8): # Beacon Frames
                global beaconCount
                beaconCount += 1
                print("This is a beacon frame")
                print(packet.show())
            elif(packet.subtype == 4): # Probe Request Frames
                global probeReqCount
                probeReqCount += 1
                print("This is a Probe Request frame")
                print(packet.show())
            elif (packet.subtype == 5): # Probe Response Frames
                global probeRespCount
                probeRespCount += 1
                print("This is a Probe Response frame")
                print(packet.show())
            elif (packet.subtype == 12):  # Deauthentication Frames
                global deauthCount
                deauthCount += 1
                print("This is a deauthentication frame")
                print(packet.show())
            elif (packet.subtype == 10):  # Disassociation Frames
                global disassCount
                disassCount += 1
                print("This is a disassociation frame")
                print(packet.show())
            else:
                global otherMgmtFrames
                otherMgmtFrames += 1
                print("Other Management Frame")
                print(packet.show())

        else:
            global others
            others += 1
            print("Any other packet")
            print(packet.show())
def main():
    dev = sys.argv[1]
    print(dev)
    print("Trying to set monitor mode for device " + dev + "...")
    os.system("ifconfig " + dev + " down")
    os.system("iwconfig " + dev + " mode monitor")
    os.system("ifconfig " + dev + " up")
    os.system("iwconfig")
    print("Done. If you don't see any data, the monitor mode setup may have failed.")


    sniff(iface="wlan0",prn=packet_callback, count = 30000)

    print('Category count')
    print('Beacon ', beaconCount)
    print('Probe Request ', probeReqCount)
    print('Probe Response ', probeRespCount)
    print('Deauthentication ', deauthCount)
    print('Disassociation ', disassCount)
    print('Other Mgmt Frames ', otherMgmtFrames)
    print('Others ', others)

    print('Total Packets Captured ', beaconCount + probeReqCount + probeRespCount + otherMgmtFrames + others)

if __name__ == "__main__":
    main()
