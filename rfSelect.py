##########################################################################
# rfSelect.py
# Author - Stephen Gannon
#
# File used for carrying out RF Selection
##########################################################################

from pandas import read_csv
from sklearn.feature_selection import RFE
from sklearn.linear_model import LogisticRegression
# load data
url = "combinedStats.csv"
names = ['lenMean', 'lenMedian', 'lenStd', 'lenVar', 'lenCoeffVar',
		 'protoMean', 'protoStd', 'protoVar', 'protoCoeffVar', 'iatMean', 
		 'iatMedian', 'iatStd', 'iatVar', 'iatCoeffVar', 'srcMean', 'srcMedian',
		 'srcStd', 'srcVar', 'srcCoeffVar', 'dstMean', 'dstMedian', 'dstStd', 
		 'dstVar', 'dstCoeffVar', 'class']
dataframe = read_csv(url, names=names)
array = dataframe.values
X = array[:,0:24]
Y = array[:,24]
# feature extraction
model = LogisticRegression(solver='lbfgs')
rfe = RFE(model, n_features_to_select=10, step=1)
fit = rfe.fit(X, Y)
print("Num Features: %d" % fit.n_features_)
print("Selected Features: %s" % fit.support_)
print("Feature Ranking: %s" % fit.ranking_)
