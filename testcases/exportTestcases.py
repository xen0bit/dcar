from os import listdir
from os.path import isfile, join
from pprint import pprint
import pickle
import json


def validateRule(rule, data):
    dataArray = bytearray(data)
    if(len(dataArray) != rule['length']):
        return False
    else:
        for piece in list(rule['positions'].keys()):
            if(dataArray[int(piece)] not in rule['positions'][piece]):
                return False
        return True

def forceRule(rule, data):
    dataArray = bytearray(data)
    if(len(dataArray) == rule['length']):
        for piece in list(rule['position'].keys()):
            if(rule['position'][piece] != dataArray[piece]):
                dataArray[piece] = rule['position'][piece]
    return bytes(dataArray)

def main():
    with open('packetRule.json', 'r') as pr:
        global packetRule
        packetRule = json.loads(pr.read())
    fuzzList = []
    onlyfiles = [f for f in listdir('./radamsa') if isfile(join('./radamsa', f))]
    for i in onlyfiles:
        #print(i)
        with open('./radamsa/' + str(i), 'rb') as f:
            fuzzList.append(f.read())
    print('Before: ' + str(len(fuzzList)))
    fuzzList = [x for x in fuzzList if validateRule(packetRule, x) == True]
    print('After: ' + str(len(fuzzList)))
    #exportObject = {'fuzz': fuzzList}
    with open('fuzzCases.pickle', 'wb') as f:
    # Pickle the 'data' dictionary using the highest protocol available.
        pickle.dump(fuzzList, f, protocol=2)
    #pprint(exportObject)

main()
