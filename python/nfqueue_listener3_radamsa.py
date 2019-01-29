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

#parser = argparse.ArgumentParser(description="Binds to queue and modifies packets that match the rule")
#parser.add_argument("pr", type=str, help="The packet rule JSON file")
#parser.add_argument("fc", type=str, help="The fuzzCases stored in binary pickle fromat")
#args = parser.parse_args()

#Radamsa Config
# Usage: radamsa [arguments] [file ...]
#   -h | --help, show this thing
#   -a | --about, what is this thing?
#   -V | --version, show program version
#   -o | --output <arg>, output pattern, e.g. out.bin /tmp/fuzz-%n.%s, -, :80 or 127.0.0.1:80 or 127.0.0.1:123/udp [-]
#   -n | --count <arg>, how many outputs to generate (number or inf) [1]
#   -s | --seed <arg>, random seed (number, default random)
#   -m | --mutations <arg>, which mutations to use [ft=2,fo=2,fn,num=5,td,tr2,ts1,tr,ts2,ld,lds,lr2,li,ls,lp,lr,lis,lrs,sr,sd,bd,bf,bi,br,bp,bei,bed,ber,uw,ui=2,xp=9,ab]
#   -p | --patterns <arg>, which mutation patterns to use [od,nd=2,bu]
#   -g | --generators <arg>, which data generators to use [random,file=1000,jump=200,stdin=100000]
#   -M | --meta <arg>, save metadata about generated files to this file
#   -r | --recursive, include files in subdirectories
#   -S | --seek <arg>, start from given testcase
#   -T | --truncate <arg>, take only first n bytes of each output (mainly intended for UDP)
#   -d | --delay <arg>, sleep for n milliseconds between outputs
#   -l | --list, list mutations, patterns and generators
#   -C | --checksums <arg>, maximum number of checksums in uniqueness filter (0 disables) [10000]
#   -H | --hash <arg>, hash algorithm for uniqueness checks (stream or sha256) [stream]
#   -v | --verbose, show progress during generation

#  Mutations (-m)
#   ab: enhance silly issues in ASCII string data handling
#   bd: drop a byte
#   bf: flip one bit
#   bi: insert a random byte
#   br: repeat a byte
#   bp: permute some bytes
#   bei: increment a byte by one
#   bed: decrement a byte by one
#   ber: swap a byte with a random one
#   sr: repeat a sequence of bytes
#   sd: delete a sequence of bytes
#   ld: delete a line
#   lds: delete many lines
#   lr2: duplicate a line
#   li: copy a line closeby
#   lr: repeat a line
#   ls: swap two lines
#   lp: swap order of lines
#   lis: insert a line from elsewhere
#   lrs: replace a line with one from elsewhere
#   td: delete a node
#   tr2: duplicate a node
#   ts1: swap one node with another one
#   ts2: swap two nodes pairwise
#   tr: repeat a path of the parse tree
#   uw: try to make a code point too wide
#   ui: insert funny unicode
#   num: try to modify a textual number
#   xp: try to parse XML and mutate it
#   ft: jump to a similar position in block
#   fn: likely clone data between similar positions
#   fo: fuse previously seen data elsewhere
#   nop: do nothing (debug/test)

# Mutation patterns (-p)
#   od: Mutate once
#   nd: Mutate possibly many times
#   bu: Make several mutations closeby once

# Generators (-g)
#  stdin: read data from standard input if no paths are given or - is among them
#  file: read data from given files
#  random: generate random data

#See parameters above
radamsaArgs = '-p od'

#Maximum number of packets to store in the RAMDisk
maxPacketsOnDisk = 1000

#Fuzz this percent of packets (AVG over time)
fuzzPercent = 0.50

#Do not change
currentPacketOnDisk = 1

#Generates the string to be executed by radamsa
def generateRadamsaParamaters():
    execute = []
    #Path to radamsa
    execute.append('radamsa')
    #Radamsa Args
    execute.append(radamsaArgs)
    #Generate fuzzed packets based on collected packets
    execute.append('-r /mnt/pktramdisk/')
    #./../radamsa/bin/radamsa -p od -r /mnt/pktramdisk/
    return ' '.join(execute)

#Respects maxPacketsOnDisk
def rollingPacketStorage(packetBytes):
    global currentPacketOnDisk, maxPacketsOnDisk
    #Rotate the packet queue on disk
    if currentPacketOnDisk > maxPacketsOnDisk:
        currentPacketOnDisk = 1
    else:
        #Writes bytes(pkt[TCP].payload) as binary to {1..maxPacketsOnDisk}.pkt
        with open('/mnt/pktramdisk/{}.pkt'.format(str(currentPacketOnDisk)), 'wb') as f:
            f.write(packetBytes)
    currentPacketOnDisk+=1

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
    proc = subprocess.check_output(generateRadamsaParamaters(), shell=True)
    return proc

def validateRule(data):
    if('Raw' in data):
            return True
    else:
        return False

def modifyPacket(pkt):
    payload_before = len(pkt[TCP].payload)
    #Send un-fuzzed packet to rolling packet storage on RAMdisk
    rollingPacketStorage(bytes(pkt[TCP].payload))
    #Fuzz packet
    newload = radamsafuzz()
    #Set the new packet
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
            #Fuzz packets ~x% of the time
            if(random.random() > fuzzPercent):
                print("BEFORE")
                packet.show2()
                packetLoadBefore = str(packet[TCP].payload)
                packet = modifyPacket(packet)
                packet = recalcChecksum(packet)
                print("AFTER")
                packet.show2()
                packetLoadAfter = str(packet[TCP].payload)
                #Color Diff
                #colordiff.packetdiff(packetLoadBefore,packetLoadAfter)
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
