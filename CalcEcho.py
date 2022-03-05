##########################################################################
# CalcEcho.py
# Author - Stephen Gannon
#
# This file takes the raw network data and calculates 24 features from it
##########################################################################

import pandas as pd
import csv

dfEcho = pd.read_csv (r'C:\Users\steph\FYP\EchoDot.csv')
dfEcho.columns = ["ip.src", "ip.dst", "ip.proto", "tcp.srcport", "udp.srcport",
	    "tcp.dstport", "udp.dstport", "frame.time_delta_displayed", "ip.len"]


###################################################################################
# Combining Echo Port values into 1 vector
dfEcho['tcp.srcport'] = dfEcho['tcp.srcport'].fillna(0)
dfEcho['tcp.dstport'] = dfEcho['tcp.dstport'].fillna(0)
dfEcho['udp.srcport'] = dfEcho['udp.srcport'].fillna(0)
dfEcho['udp.dstport'] = dfEcho['udp.dstport'].fillna(0)

EchoSrcPort = dfEcho['tcp.srcport'] + dfEcho['udp.srcport']
dfEcho['srcport'] = EchoSrcPort
EchoDstPort = dfEcho['tcp.dstport'] + dfEcho['udp.dstport']
dfEcho['dstport'] = EchoDstPort


####################################################################################
#Echo IP Length Calculations
lenEchoMean = dfEcho['ip.len'].mean()
lenEchoMedian = dfEcho['ip.len'].median()
lenEchoStd = dfEcho['ip.len'].std()
lenEchoVar = dfEcho['ip.len'].var()
lenEchoCoeffVar = lenEchoStd/lenEchoMean

####################################################################################
#Echo IP Proto Calculations
protoEchoMean = dfEcho['ip.proto'].mean()
protoEchoStd = dfEcho['ip.proto'].std()
protoEchoVar = dfEcho['ip.proto'].var()
protoEchoCoeffVar = protoEchoStd/protoEchoMean

######################################################################################
#Echo IAT Calculations
iatEchoMean = dfEcho['frame.time_delta_displayed'].mean()
iatEchoMedian = dfEcho['frame.time_delta_displayed'].median()
iatEchoStd = dfEcho['frame.time_delta_displayed'].std()
iatEchoVar = dfEcho['frame.time_delta_displayed'].var()
iatEchoCoeffVar = iatEchoStd/iatEchoMean

########################################################################################
#Echo Source Port Calculations
srcEchoMean = dfEcho['srcport'].mean()
srcEchoMedian = dfEcho['srcport'].median()
srcEchoStd = dfEcho['srcport'].std()
srcEchoVar = dfEcho['srcport'].var()
srcEchoCoeffVar = srcEchoStd/srcEchoMean

########################################################################################
#Echo Destination Port Calculations
dstEchoMean = dfEcho['dstport'].mean()
dstEchoMedian = dfEcho['dstport'].median()
dstEchoStd = dfEcho['dstport'].std()
dstEchoVar = dfEcho['dstport'].var()
dstEchoCoeffVar = dstEchoStd/dstEchoMean

########################################################################################
# Store computed values for first N packets in csv row

EchoStats = pd.DataFrame([lenEchoMean, lenEchoMedian, lenEchoStd, lenEchoVar, lenEchoCoeffVar,
		 protoEchoMean, protoEchoStd, protoEchoVar, protoEchoCoeffVar, iatEchoMean, 
		 iatEchoMedian, iatEchoStd, iatEchoVar, iatEchoCoeffVar, srcEchoMean, srcEchoMedian,
		 srcEchoStd, srcEchoVar, srcEchoCoeffVar, dstEchoMean, dstEchoMedian, dstEchoStd, 
		 dstEchoVar, dstEchoCoeffVar, 0], index=None, columns=None)
EchoStats = EchoStats.T
EchoStats.to_csv('EchoStats.csv', mode='a', index=False, header=False)
