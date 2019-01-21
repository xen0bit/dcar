from scapy.all import *
from pprint import pprint
import json
import collections
import statistics
import argparse

# rdpcap comes from scapy and loads in our pcap file
parser = argparse.ArgumentParser(description="Generate a fuzzy rule to filter for common packet structure")
parser.add_argument("fileName", type=str, help="the PCAP file")
parser.add_argument("do", type=int, help="DROP OUTLIER packets with count below this value")
parser.add_argument("pl", type=int, help="PICK LENGTH of packet you'd like to generate a rule for")
parser.add_argument("st", type=int, help="SET THRESHOLD count for an attribute to apprear in generated ruleset")
args = parser.parse_args()


packets = rdpcap(args.fileName)


def countByLength():
    # Let's iterate through every packet
    counts = {}
    for packet in packets:
        if('Raw' in packet):
            lenOfPacket = len(bytearray(packet['Raw'].load))
            if lenOfPacket not in counts:
                counts[lenOfPacket] = 1
            else:
                counts[lenOfPacket] = counts[lenOfPacket] + 1
    pprint(counts)
    return counts


def calcStdDeviation(countsObject, filterLessThan):
    lengths = []
    for item in countsObject:
        if(countsObject[item] > filterLessThan):
            lengths.append(countsObject[item])
    mean = statistics.mean(lengths)
    print("Mean (AVG) of sample is % s " % mean)
    stdev = statistics.stdev(lengths)
    print("Standard Deviation of sample is % s " % stdev)
    for item in list(countsObject.keys()):
        if((countsObject[item] < (mean-stdev)) or (countsObject[item] > (mean+stdev))):
            del countsObject[item]
    for i in countsObject:
        shannonByLength(i)
    return


def shannon(s):
    probabilities = [n_x/len(s) for x, n_x in collections.Counter(s).items()]
    e_x = [-p_x*math.log(p_x, 2) for p_x in probabilities]
    return sum(e_x)


def shannonByLength(length):
    forShannon = bytearray()
    for packet in packets:
        if('Raw' in packet and len(bytearray(packet['Raw'].load)) == length):
            currentPacket = bytearray(packet['Raw'].load)
            for i in range(length):
                forShannon.append(currentPacket[i])
    print("Shannon for length " + str(length) + ": " + str(shannon(forShannon)))


def traitsByLength(length):
    traits = {}
    for i in range(length):
        traits[i] = {}
    for packet in packets:
        if('Raw' in packet and len(bytearray(packet['Raw'].load)) == length):
            for i in range(length):
                byteFromPos = bytearray(packet['Raw'].load)[i]
                if byteFromPos not in traits[i]:
                    traits[i][byteFromPos] = 1
                else:
                    traits[i][byteFromPos] = traits[i][byteFromPos] + 1
    return traits


def filter_by_threshold(threshold, traits):
    for piece in list(traits.keys()):
        for byteValue in list(traits[piece].keys()):
            if traits[piece][byteValue] < threshold:
                del traits[piece][byteValue]
    for piece in list(traits.keys()):
        if traits[piece] == {}:
            del traits[piece]
    return traits


def exportRule(traitsObject, lengthOfPacket):
    exportObject = {}
    exportObject['length'] = int(lengthOfPacket)
    exportObject['positions'] = {}
    listOfPositions = list(traitsObject.keys())
    for i in listOfPositions:
        exportObject['positions'][i] = []
    for i in listOfPositions:
        #exportObject['positions'][i].append(traitsObject[i].keys())
        for x in list(traitsObject[i].keys()):
            exportObject['positions'][i].append(x)
    print(exportObject)
    return exportObject
    


def main():
    #counts = countByLength()
    #calcStdDeviation(counts, 100)
    countByLength()
    dropOutliersBelowCount = int(args.do)
    counts = calcStdDeviation(countByLength(), dropOutliersBelowCount)
    create_schema_for = int(args.pl)
    threshold_count = int(args.st)
    traits = traitsByLength(create_schema_for)
    for i in range(1, threshold_count):
        print("Threshold: " + str(i))
        pprint(filter_by_threshold(i, traits))
    shannonByLength(create_schema_for)
    with open('packetRule.json', 'w') as outfile:
        json.dump(exportRule(filter_by_threshold(threshold_count, traits), create_schema_for), outfile)


main()

