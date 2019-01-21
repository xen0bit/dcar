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

parser = argparse.ArgumentParser(description="Binds to queue and modifies packets that match the rule")
parser.add_argument("pr", type=str, help="The packet rule JSON file")
parser.add_argument("fc", type=str, help="The fuzzCases stored in binary pickle fromat")
args = parser.parse_args()


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

def validateRule(rule, data):
    if('Raw' in data):
        #Note minor change from other validate rule functions
        dataArray = bytearray(data['Raw'].load)
        if(len(dataArray) != rule['length']):
            return False
        else:
            for piece in list(rule['positions'].keys()):
                if(dataArray[int(piece)] not in rule['positions'][piece]):
                    return False
            return True
    else:
        return False

def modifyPacket(pkt):
    payload_before = len(pkt[TCP].payload)
    print('Fuzzing with: ')
    fuzzcase = bytes(next(fuzzCases))
    print(fuzzcase)
    pkt['Raw'].load = fuzzcase
    #pkt[TCP].payload = str(pkt[TCP].payload).replace("Welcome","NIEVE  ")
    ############
    #substitute = bytearray(pkt['Raw'].load)
    #substitute[10] = substitute[10]+1
    #pkt['Raw'].load = bytes(substitute)
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
        #print("BEFORE")
        packet = IP(pkt.get_payload())
        if(validateRule(packetRule, packet)):
            print("MATCHED RULE")
            packet.show2()
            packet = modifyPacket(packet)
            packet = recalcChecksum(packet)
            packet.show2()
            pkt.set_payload(raw(packet))
            pkt.accept()
        else:
            #pprint(packet)
            pkt.accept()

loadPacketRuleGlobal()
loadFuzzedPacketsGlobal()
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
