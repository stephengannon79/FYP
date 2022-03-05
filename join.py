##########################################################################
# join.py
# Author - Stephen Gannon
#
# This file takes the benign and attack test data and combines then 
# for feature selection testing
##########################################################################

import csv
import pandas as pd

atkReader = csv.reader(open("atkStats.csv"))
nomReader = csv.reader(open("nomStats.csv"))

combinedStats = open("combinedStats.csv", "w")

writer = csv.writer(combinedStats)

for row in nomReader:
	writer.writerow(row)
for row in atkReader:
	writer.writerow(row)

combinedStats.close()

df = pd.read_csv('combinedStats.csv')
df.to_csv('combinedStats.csv', index=False)

