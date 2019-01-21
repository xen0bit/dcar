#Developed in Python 3.6

from scapy.all import *
from netfilterqueue import NetfilterQueue
import socket
from pprint import pprint
import json
import os
import sys
import logging
import pickle
import argparse
import random

#parser = argparse.ArgumentParser(description="Binds to queue and modifies packets that match the rule")
#parser.add_argument("pr", type=str, help="The packet rule JSON file")
#parser.add_argument("fc", type=str, help="The fuzzCases stored in binary pickle fromat")
#args = parser.parse_args()


try:
    QUEUE_NUM = int(os.getenv('QUEUE_NUM', 1))
except ValueError as e:
    sys.stderr.write('Error: env QUEUE_NUM must be integer\n')
    sys.exit(1)

def loadFuzzedPacketsGlobal():
    with open(args.fc, 'rb') as f:
        global fuzzCases
        fuzzCases = iter(pickle.loads(f.read()))


def loadPacketRuleGlobal():
    with open(args.pr, 'r') as f:
        global packetRule
        packetRule = json.loads(f.read())

def radamsafuzz():
    proc = subprocess.check_output('./../radamsa/bin/radamsa /mnt/pktramdisk/in.pkt', shell=True)
    return proc

def validateRule(data):
    if('Raw' in data):
            return True
    else:
        return False

def modifyPacket(pkt):
    payload_before = len(pkt[TCP].payload)
    with open('/mnt/pktramdisk/in.pkt', 'wb') as f:
        f.write(bytes(pkt[TCP].payload))
    newload = radamsafuzz()
    #print(newload)
    pkt['Raw'].load = bytes(newload)
    #pkt[TCP].payload = str(pkt[TCP].payload).replace("A","B")
    ############
    payload_after = len(pkt[TCP].payload)
    payload_dif = payload_after - payload_before
    pkt[IP].len = pkt[IP].len + payload_dif
    #pkt.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt)+ payload_dif )
    
    return pkt

def recalcChecksum(pkt):
    del pkt[IP].chksum
    del pkt[TCP].chksum
    #The above are recalculated after deletion automatically
    return pkt

def callback(pkt):
        packet = IP(pkt.get_payload())
        if(validateRule(packet)):
            #Fuzz packets ~75% of the time
            if(random.random() > 0.75):
                print("BEFORE")
                packet.show2()
                packet = modifyPacket(packet)
                packet = recalcChecksum(packet)
                print("AFTER")
                packet.show2()
                pkt.set_payload(raw(packet))
                pkt.accept()
            else:
                pkt.accept()
        else:
            pkt.accept()

#loadPacketRuleGlobal()
#loadFuzzedPacketsGlobal()
sys.stdout.write('Listening on NFQUEUE queue-num %s... \n' % str(QUEUE_NUM))

nfqueue = NetfilterQueue()
nfqueue.bind(QUEUE_NUM, callback)
s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
try:
    nfqueue.run_socket(s)
except KeyboardInterrupt:
    sys.stdout.write('Exiting \n')

s.close()
nfqueue.unbind()
