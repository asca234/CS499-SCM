#Adrian Carideo
#data collection for CS371 Project - Spring ‘19

from scapy.all import *
import sys
import socket 
import os

#expected usage: sudo python pktSniff.py label startingFlowID
#where label is youtube, skype, fileDownload, etc
#and startingFlowID is the first flowID to use, 0 if first dataset generated
#wise, but optional, to redirect output to appropriately named file; ^usage^ > youtube.txt 
label = sys.argv[1]
currFlowID = sys.argv[2]
    
#flow detection variables
currFlowID = int(currFlowID) - 1 #first flow will be ID 0
#2d list of lists, inner list is flow data, form of:
#[srcIP, srcPort, dstIP, dstPort, protocol]
flows = []
#list of flow IDs, flowID[i] is ID of flows[i]
flowIDs = []

#tcp = 0
#udp = 1
#callback for sniff
def detectFlows(x):
    #data fields to pull
    global currFlowID
    srcIP = x[IP].src
    dstIP = x[IP].dst
    #scapy encodes tcp as 6, udp as 17 internally
    proto = 0 if x[IP].proto == 6 else 1 if x[IP].proto == 17 else "other"
    length = x[IP].len
    srcPort = x[TCP].sport if proto == 0 else x[UDP].sport if proto == 1 else "other"
    dstPort = x[TCP].dport if proto == 0 else x[UDP].dport if proto == 1 else "other"
    #determine flow id
    if [srcIP, srcPort, dstIP, dstPort, proto] in flows:
        flowID = flowIDs[flows.index([srcIP, srcPort, dstIP, dstPort, proto])]
    elif [dstIP, dstPort, srcIP, srcPort, proto] in flows:
        flowID = flowIDs[flows.index([dstIP, dstPort, srcIP, srcPort, proto])]
    else:
        currFlowID += 1
        flowID = currFlowID
        flows.append([srcIP, srcPort, dstIP, dstPort, proto])
        flowIDs.append(flowID)
    #output the formatted packet info
    print flowID, srcIP, dstIP, proto, srcPort, dstPort, length, label

index = 0
while index < 250:
#the filter blocks nonTCP, nonUDP, and all SSH packets(we've had to use	this on the Netlab VMs via SSH)
    pkts = sniff(filter = "tcp or udp and not port 22", prn = detectFlows, count = 100)
    index = index+1

