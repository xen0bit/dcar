from scapy.all import *
import random
chatTripper = False

def itemSwap():
    temp = bytearray(b']\x01\x03\xe4\xff')
    for i in range(2,4):
        temp[i] = random.randrange(0,255)
    return bytes(temp)

def modifyItem(pkt):
    if(b']\x01\x03\xe4\xff' in pkt['Raw'].load):
        pkt['Raw'].load = pkt['Raw'].load.replace(b']\x01\x03\xe4\xff', itemSwap(), 1)
        #print(str(pkt[TCP].payload))
        print('MODIFIED PACKET')
        #chatTripper = False
    return pkt

def listSplit(pkt):
    if(b'Magic' in pkt['Raw'].load):
        print(pkt)
    #delimited = pkt['Raw'].load.split(b'\x00')
    #for i in delimited:
    #    print(i)
    return pkt

def fuzz(pkt):
    load = pkt['Raw'].load
    loadBytes = bytearray(load)
    randByte = random.randrange(0,255)
    randPlacemant = random.randrange(0,len(loadBytes))
    loadBytes[randPlacemant] = randByte
    pkt['Raw'].load = bytes(loadBytes)
    return pkt

def printPacket(pkt):
    print(pkt['Raw'].load)
    return pkt

def test(pkt):
    if(b'\x80\x80\x80\x80\x80\x80' in pkt['Raw'].load):
        pkt['Raw'].load = pkt['Raw'].load.replace(b'\x80\x80\x80\x80\x80\x80', b'\x90\x90\x90\x90\x90\x90', 1)
        #print(str(pkt[TCP].payload))
        print('MODIFIED PACKET')
        #chatTripper = False
    return pkt