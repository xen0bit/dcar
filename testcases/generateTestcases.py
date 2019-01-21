from scapy.all import *
from pprint import pprint
import json
import hashlib
import argparse

parser = argparse.ArgumentParser(description="Write packet load data that matches fuzzy rule as binary files to feed into a fuzzer")
parser.add_argument("fileName", type=str, help="the PCAP file")
args = parser.parse_args()

def validateRule(rule, data):
    dataArray = bytearray(data)
    if(len(dataArray) != rule['length']):
        return False
    else:
        for piece in list(rule['positions'].keys()):
            if(dataArray[int(piece)] not in rule['positions'][piece]):
                return False
        return True

def dumpSamples():
    packets = rdpcap(args.fileName)
    m = hashlib.md5()
    for packet in packets:
        if('Raw' in packet):
            if(validateRule(packetRule, packet['Raw'].load)):
                #pprint(packet['Raw'].load)
                m.update(packet['Raw'].load)
                #print(m.hexdigest())
                with open('./dump/' + str(m.hexdigest()),'wb') as f:
                    f.write(bytearray(packet['Raw'].load))

def main():
    with open('packetRule.json', 'r') as f:
        global packetRule
        packetRule = json.loads(f.read())
    pprint(packetRule)
    dumpSamples()

main()
