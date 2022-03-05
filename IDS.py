##########################################################################
# IDS.py
# Author - Stephen Gannon
#
# Initial staistics-based intrusion detetcion system
##########################################################################

import pandas as pd
import csv
import time

#dfCap = pd.read_csv (r'C:\Users\steph\FYP\TestLight.csv')
dfCap = pd.read_csv (r'C:\Users\steph\FYP\TestEcho.csv')

i = 0
average = 0
device = 0

#########################################################################
## Start identification by parsing first 5 25 packet combinations 
#########################################################################

meanLength1 = dfCap.iloc[i,0]
stdLength1 = dfCap.iloc[i,2]
medianIat1 = dfCap.iloc[i,10]
meanSrcPort1 = dfCap.iloc[i,14]
medianSrcPort1 = dfCap.iloc[i,15]
srcCoeffVar1 = dfCap.iloc[i,18]
medianDstPort1 = dfCap.iloc[i,20]

meanLength2 = dfCap.iloc[i+1,0]
stdLength2 = dfCap.iloc[i+1,2]
medianIat2 = dfCap.iloc[i+1,10]
meanSrcPort2 = dfCap.iloc[i+1,14]
medianSrcPort2 = dfCap.iloc[i+1,15]
srcCoeffVar2 = dfCap.iloc[i+1,18]
medianDstPort2 = dfCap.iloc[i+1,20]

meanLength3 = dfCap.iloc[i+2,0]
stdLength3 = dfCap.iloc[i+2,2]
medianIat3 = dfCap.iloc[i+2,10]
meanSrcPort3 = dfCap.iloc[i+2,14]
medianSrcPort3 = dfCap.iloc[i+2,15]
srcCoeffVar3 = dfCap.iloc[i+2,18]
medianDstPort3 = dfCap.iloc[i+2,20]

meanLength4 = dfCap.iloc[i+3,0]
stdLength4 = dfCap.iloc[i+3,2]
medianIat4 = dfCap.iloc[i+3,10]
meanSrcPort4 = dfCap.iloc[i+3,14]
medianSrcPort4 = dfCap.iloc[i+3,15]
srcCoeffVar4 = dfCap.iloc[i+3,18]
medianDstPort4 = dfCap.iloc[i+3,20]

meanLength5 = dfCap.iloc[i+4,0]
stdLength5 = dfCap.iloc[i+4,2]
medianIat5 = dfCap.iloc[i+4,10]
meanSrcPort5 = dfCap.iloc[i+4,14]
medianSrcPort5 = dfCap.iloc[i+4,15]
srcCoeffVar5 = dfCap.iloc[i+4,18]
medianDstPort5 = dfCap.iloc[i+4,20]

sum1 = (meanLength1+stdLength1+medianIat1+meanSrcPort1+medianSrcPort1+srcCoeffVar1+medianDstPort1)
sum2 = (meanLength2+stdLength2+medianIat2+meanSrcPort2+medianSrcPort2+srcCoeffVar2+medianDstPort2)
sum3 = (meanLength3+stdLength3+medianIat3+meanSrcPort3+medianSrcPort3+srcCoeffVar3+medianDstPort3)
sum4 = (meanLength4+stdLength4+medianIat4+meanSrcPort4+medianSrcPort4+srcCoeffVar4+medianDstPort4)
sum5 = (meanLength5+stdLength5+medianIat5+meanSrcPort5+medianSrcPort5+srcCoeffVar5+medianDstPort5)

average = (sum1+sum2+sum3+sum4+sum5)/5
i = i+5

if average > 12000 and average < 31000:
	print("~~~Device Type Identified as 'Philips HUE smart LED lamp'~~~")
	device = 1
	AFV = 0.6558
elif average >68000 and average <87500:
	print("~~~Device Type Identified as 'Amazon Echo Home'~~~")
	device = 2
	AFV = 2.88
else:
	print("~~~Device Type Identified as 'Unrecognised Device'~~~")

#########################################################################
## Depending on Device Type detected, Load Fingerprint Values relating 
## to applicable Device for use in Attack Detection
#########################################################################

if device == 1:
	Aval = 218.5
elif device == 2:
	Aval = 1048

if device == 1:
	Cval = 164.4
elif device == 2:
	Cval = 1081

if device == 1:
	Kval = 0.047
elif device == 2:
	Kval = 0.0003

if device == 1:
	Oval = 11654
elif device == 2:
	Oval = 24953

if device == 1:
	Pval = 1900
elif device == 2:
	Pval = 24428

if device == 1:
	Sval = 1.52
elif device == 2:
	Sval = 1.03

if device == 1:
	Uval = 1900
elif device == 2:
	Uval = 26697

if device == 1:
	lower = 0.25
	upper = 1.5
elif device == 2:
	lower = 1.75
	upper = 3.5

#########################################################################
## Begin parsing incoming traffic and calculate if Aggregate Fingerprint 
## Value (AFV) is nominal for particular device type
#########################################################################

while AFV > lower and AFV < upper:
	meanLength1 = dfCap.iloc[i,0]
	stdLength1 = dfCap.iloc[i,2]
	medianIat1 = dfCap.iloc[i,10]
	meanSrcPort1 = dfCap.iloc[i,14]
	medianSrcPort1 = dfCap.iloc[i,15]
	srcCoeffVar1 = dfCap.iloc[i,18]
	medianDstPort1 = dfCap.iloc[i,20]

	A1 = abs((meanLength1-Aval)/Aval)
	C1 = abs((stdLength1-Cval)/Cval)
	K1 = abs((medianIat1-Kval)/Kval)
	O1 = abs((meanSrcPort1-Oval)/Oval)
	P1 = abs((medianSrcPort1-Pval)/Pval)
	S1 = abs((srcCoeffVar1-Sval)/Sval)
	U1 = abs((medianDstPort1-Uval)/Uval)

	#######################################################
	meanLength2 = dfCap.iloc[i+1,0]
	stdLength2 = dfCap.iloc[i+1,2]
	medianIat2 = dfCap.iloc[i+1,10]
	meanSrcPort2 = dfCap.iloc[i+1,14]
	medianSrcPort2 = dfCap.iloc[i+1,15]
	srcCoeffVar2 = dfCap.iloc[i+1,18]
	medianDstPort2 = dfCap.iloc[i+1,20]

	A2 = abs((meanLength2-Aval)/Aval)
	C2 = abs((stdLength2-Cval)/Cval)
	K2 = abs((medianIat2-Kval)/Kval)
	O2 = abs((meanSrcPort2-Oval)/Oval)
	P2 = abs((medianSrcPort2-Pval)/Pval)
	S2 = abs((srcCoeffVar2-Sval)/Sval)
	U2 = abs((medianDstPort2-Uval)/Uval)

	#######################################################
	meanLength3 = dfCap.iloc[i+2,0]
	stdLength3 = dfCap.iloc[i+2,2]
	medianIat3 = dfCap.iloc[i+2,10]
	meanSrcPort3 = dfCap.iloc[i+2,14]
	medianSrcPort3 = dfCap.iloc[i+2,15]
	srcCoeffVar3 = dfCap.iloc[i+2,18]
	medianDstPort3 = dfCap.iloc[i+2,20]

	A3 = abs((meanLength3-Aval)/Aval)
	C3 = abs((stdLength3-Cval)/Cval)
	K3 = abs((medianIat3-Kval)/Kval)
	O3 = abs((meanSrcPort3-Oval)/Oval)
	P3 = abs((medianSrcPort3-Pval)/Pval)
	S3 = abs((srcCoeffVar3-Sval)/Sval)
	U3 = abs((medianDstPort3-Uval)/Uval)

	#######################################################
	meanLength4 = dfCap.iloc[i+3,0]
	stdLength4 = dfCap.iloc[i+3,2]
	medianIat4 = dfCap.iloc[i+3,10]
	meanSrcPort4 = dfCap.iloc[i+3,14]
	medianSrcPort4 = dfCap.iloc[i+3,15]
	srcCoeffVar4 = dfCap.iloc[i+3,18]
	medianDstPort4 = dfCap.iloc[i+3,20]

	A4 = abs((meanLength4-Aval)/Aval)
	C4 = abs((stdLength4-Cval)/Cval)
	K4 = abs((medianIat4-Kval)/Kval)
	O4 = abs((meanSrcPort4-Oval)/Oval)
	P4 = abs((medianSrcPort4-Pval)/Pval)
	S4 = abs((srcCoeffVar4-Sval)/Sval)
	U4 = abs((medianDstPort4-Uval)/Uval)

	#######################################################
	meanLength5 = dfCap.iloc[i+4,0]
	stdLength5 = dfCap.iloc[i+4,2]
	medianIat5 = dfCap.iloc[i+4,10]
	meanSrcPort5 = dfCap.iloc[i+4,14]
	medianSrcPort5 = dfCap.iloc[i+4,15]
	srcCoeffVar5 = dfCap.iloc[i+4,18]
	medianDstPort5 = dfCap.iloc[i+4,20]

	A5 = abs((meanLength5-Aval)/Aval)
	C5 = abs((stdLength5-Cval)/Cval)
	K5 = abs((medianIat5-Kval)/Kval)
	O5 = abs((meanSrcPort5-Oval)/Oval)
	P5 = abs((medianSrcPort5-Pval)/Pval)
	S5 = abs((srcCoeffVar5-Sval)/Sval)
	U5 = abs((medianDstPort5-Uval)/Uval)

	#######################################################

	AFV1 = (A1+C1+K1+O1+P1+S1+U1)
	AFV2 = (A2+C2+K2+O2+P2+S2+U2)
	AFV3 = (A3+C3+K3+O3+P3+S3+U3)
	AFV4 = (A4+C4+K4+O4+P4+S4+U4)
	AFV5 = (A5+C5+K5+O5+P5+S5+U5)

	AFV = (AFV1+AFV2+AFV3+AFV4+AFV5)/5
	print (AFV)
	i = i + 5
	print("Behaviour As Expected")
	#Sleep for visual testing
	#time.sleep(0.1) 

print("Anomolous Behaviour Detected")
print(i)
