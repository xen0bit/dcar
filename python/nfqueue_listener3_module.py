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
import colordiff
import osrs as osrs
import rl as rl

parser = argparse.ArgumentParser(description="Binds to queue and modifies packets that match the rule")
parser.add_argument("proto", type=str, help="tcp or udp")
parser.add_argument("sourceport", type=str, help="The destination port to modify traffic for")
args = parser.parse_args()

#Fuzz this percent of packets (AVG over time)
fuzzPercent = 0.15

#Do not change
currentPacketOnDisk = 1

def setSystemFilter(proto, sourceport):
    print('Routing traffic to nfqueue...')
    command = 'sudo iptables -t raw -A PREROUTING -p $PROTO --source-port $PORT -j NFQUEUE --queue-num 1'
    command = command.replace('$PROTO', str(proto))
    command = command.replace('$PORT', str(sourceport))
    print(command)
    proc = subprocess.check_output(command, shell=True)

def resetSystemFilter():
    print('Flushing IP tables')
    command = 'sudo iptables -F -t raw'
    print(command)
    proc = subprocess.check_output(command, shell=True)

#Create nfqueue
setSystemFilter(args.proto, args.sourceport)
#Check that there is an instantiated nfqueue
try:
    QUEUE_NUM = int(os.getenv('QUEUE_NUM', 1))
except ValueError as e:
    sys.stderr.write('Error: env QUEUE_NUM must be integer\n')
    sys.exit(1)

def validateRule(data):
    if(('Raw' in data) and (random.random() < fuzzPercent)):
            return True
    else:
        return False

def modifyPacket(pkt):
    payload_before = len(pkt[TCP].payload)
    #Send un-fuzzed packet to rolling packet storage on RAMdisk
    #rollingPacketStorage(bytes(pkt[TCP].payload))
    #Fuzz packet
    #newload = radamsafuzz()
    #Set the new packet
    #pkt['Raw'].load = bytes(newload)
    #pkt[TCP].payload = str(pkt[TCP].payload).replace("A","B")
    print(pkt['Raw'].load)
    pkt['Raw'].load = str(pkt['Raw'].load).replace("domain","comain")
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
    #Does Packet have 'Raw' Data
    if(validateRule(packet)):
        #Fuzz packets ~x% of the time
        #print("BEFORE")
        #packet.show2()
        packetLoadBefore = str(packet[TCP].payload)
        #packet = modifyPacket(packet)
        packet = osrs.fuzz(packet)
        #packet = rl.listSplit(packet)
        packet = recalcChecksum(packet)
        #print("AFTER")
        #packet.show2()
        packetLoadAfter = str(packet[TCP].payload)
        #Color Diff
        if(packetLoadBefore != packetLoadAfter):
            colordiff.packetdiff(packetLoadBefore,packetLoadAfter)
        pkt.set_payload(raw(packet))

        pkt.accept()
    else:
        pkt.accept()

sys.stdout.write('Listening on NFQUEUE queue-num %s... \n' % str(QUEUE_NUM))

nfqueue = NetfilterQueue()
nfqueue.bind(QUEUE_NUM, callback)
s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
try:
    nfqueue.run_socket(s)
except KeyboardInterrupt:
    sys.stdout.write('Exiting \n')
    resetSystemFilter()
    

s.close()
nfqueue.unbind()
