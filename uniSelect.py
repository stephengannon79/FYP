##########################################################################
# uniSelect.py
# Author - Stephen Gannon
#
# File used for carrying out univariate statistical Selection
##########################################################################

from pandas import read_csv
import csv
import pandas as pd
import numpy as np
from numpy import set_printoptions
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import chi2
from sklearn.feature_selection import f_classif
from sklearn import preprocessing

# load data
filename = "combinedStats.csv"
names = ['lenMean', 'lenMedian', 'lenStd', 'lenVar', 'lenCoeffVar',
		 'protoMean', 'protoStd', 'protoVar', 'protoCoeffVar', 'iatMean', 
		 'iatMedian', 'iatStd', 'iatVar', 'iatCoeffVar', 'srcMean', 'srcMedian',
		 'srcStd', 'srcVar', 'srcCoeffVar', 'dstMean', 'dstMedian', 'dstStd', 
		 'dstVar', 'dstCoeffVar', 'class']
dataframe = read_csv(filename, names=names)
array = dataframe.values
X = array[:,0:24]
Y = array[:,24]
# feature extraction
test = SelectKBest(score_func=f_classif, k=10)
fit = test.fit(X, Y)
# summarize scores
set_printoptions(precision=3)
print(fit.scores_)

df = pd.DataFrame(fit.scores_)
df.to_csv("features.csv", index=False, header=True)
pd.read_csv('features.csv', header=None).T.to_csv('features.csv', header=['Null', 'lenMean', 'lenMedian', 'lenStd', 'lenVar', 'lenCoeffVar',
		 'protoMean', 'protoStd', 'protoVar', 'protoCoeffVar', 'iatMean', 
		 'iatMedian', 'iatStd', 'iatVar', 'iatCoeffVar', 'srcMean', 'srcMedian',
		 'srcStd', 'srcVar', 'srcCoeffVar', 'dstMean', 'dstMedian', 'dstStd', 
		 'dstVar', 'dstCoeffVar'], index=False)

df = pd.read_csv('features.csv')
first_column = df.columns[0]
df = df.drop([first_column], axis=1)
df.to_csv('features.csv', index=False)
