##########################################################################
# CalcLight.py
# Author - Stephen Gannon
#
# This file takes the raw network data and calculates 24 features from it
##########################################################################

import pandas as pd
import csv

dfLight = pd.read_csv (r'C:\Users\steph\FYP\Light.csv')
dfLight.columns = ["ip.src", "ip.dst", "ip.proto", "tcp.srcport", "udp.srcport",
	    "tcp.dstport", "udp.dstport", "frame.time_delta_displayed", "ip.len"]


###################################################################################
# Combining Light Port values into 1 vector
dfLight['tcp.srcport'] = dfLight['tcp.srcport'].fillna(0)
dfLight['tcp.dstport'] = dfLight['tcp.dstport'].fillna(0)
dfLight['udp.srcport'] = dfLight['udp.srcport'].fillna(0)
dfLight['udp.dstport'] = dfLight['udp.dstport'].fillna(0)

LightSrcPort = dfLight['tcp.srcport'] + dfLight['udp.srcport']
dfLight['srcport'] = LightSrcPort
LightDstPort = dfLight['tcp.dstport'] + dfLight['udp.dstport']
dfLight['dstport'] = LightDstPort


####################################################################################
#Light IP Length Calculations
lenLightMean = dfLight['ip.len'].mean()
lenLightMedian = dfLight['ip.len'].median()
lenLightStd = dfLight['ip.len'].std()
lenLightVar = dfLight['ip.len'].var()
lenLightCoeffVar = lenLightStd/lenLightMean

####################################################################################
#Light IP Proto Calculations
protoLightMean = dfLight['ip.proto'].mean()
protoLightStd = dfLight['ip.proto'].std()
protoLightVar = dfLight['ip.proto'].var()
protoLightCoeffVar = protoLightStd/protoLightMean

######################################################################################
#Light IAT Calculations
iatLightMean = dfLight['frame.time_delta_displayed'].mean()
iatLightMedian = dfLight['frame.time_delta_displayed'].median()
iatLightStd = dfLight['frame.time_delta_displayed'].std()
iatLightVar = dfLight['frame.time_delta_displayed'].var()
iatLightCoeffVar = iatLightStd/iatLightMean

########################################################################################
#Light Source Port Calculations
srcLightMean = dfLight['srcport'].mean()
srcLightMedian = dfLight['srcport'].median()
srcLightStd = dfLight['srcport'].std()
srcLightVar = dfLight['srcport'].var()
srcLightCoeffVar = srcLightStd/srcLightMean

########################################################################################
#Light Destination Port Calculations
dstLightMean = dfLight['dstport'].mean()
dstLightMedian = dfLight['dstport'].median()
dstLightStd = dfLight['dstport'].std()
dstLightVar = dfLight['dstport'].var()
dstLightCoeffVar = dstLightStd/dstLightMean

########################################################################################
# Store computed values for first N packets in csv row

LightStats = pd.DataFrame([lenLightMean, lenLightMedian, lenLightStd, lenLightVar, lenLightCoeffVar,
		 protoLightMean, protoLightStd, protoLightVar, protoLightCoeffVar, iatLightMean, 
		 iatLightMedian, iatLightStd, iatLightVar, iatLightCoeffVar, srcLightMean, srcLightMedian,
		 srcLightStd, srcLightVar, srcLightCoeffVar, dstLightMean, dstLightMedian, dstLightStd, 
		 dstLightVar, dstLightCoeffVar, 0], index=None, columns=None)
LightStats = LightStats.T
LightStats.to_csv('LightStats.csv', mode='a', index=False, header=False)
