##########################################################################
# predict_GRU.py
# Author - Stephen Gannon
#
# DL-based intrusion detection system (GRU)
##########################################################################

import torch
import torch.nn as nn
import numpy as np
from pandas import read_csv
from matplotlib import pyplot
from sklearn.preprocessing import MinMaxScaler


dataset = read_csv('GRULight.csv')
#print(dataset.shape)
# values = dataset.values
# # specify columns to plot
# groups = [0]
# i = 1
# # plot each column
# pyplot.figure()
# for group in groups:
# 	pyplot.subplot(len(groups), 1, i)
# 	pyplot.plot(values[:, group])
# 	pyplot.title(dataset.columns[group], y=0.5, loc='right')
# 	i += 1
# pyplot.show()

AFVdata = dataset.values.astype(float)
#print(AFVdata)

test_data_size = 30
train_data = AFVdata[:-test_data_size]
test_data = AFVdata[-test_data_size:]

# print(len(train_data))
# print(len(test_data))
# print(test_data)

scale = MinMaxScaler(feature_range=(0, 1))
norm_train_data = scale.fit_transform(train_data .reshape(-1, 1))

# print(norm_train_data[:30])
# print(norm_train_data[-5:])

norm_train_data = torch.FloatTensor(norm_train_data).view(-1)
window_size = 30

def in_out_sequence(input_data, ws):
    in_out_seq = []
    length = len(input_data)
    for i in range(length-ws):
        train_seq = input_data[i:i+ws]
        train_label = input_data[i+ws:i+ws+1]
        in_out_seq.append((train_seq ,train_label))
    return in_out_seq

train_in_out_seq = in_out_sequence(norm_train_data, window_size)

#print(len(train_in_out_seq))
#print(train_in_out_seq[:5])

class GRU(nn.Module):
    def __init__(self, input_size=1, output_size=1, n_layers=1, hidden_layer_size=100):
        super().__init__()
        self.hidden_layer_size = hidden_layer_size
        self.gru = nn.GRU(input_size, hidden_layer_size, n_layers)
        self.linear = nn.Linear(hidden_layer_size, output_size)        
        self.hidden_cell = (torch.zeros(1,1,self.hidden_layer_size))
        
    def forward(self, input_seq):
        gru_out, self.hidden_cell = self.gru(input_seq.view(len(input_seq) ,1, -1), self.hidden_cell)
        pred = self.linear(gru_out.view(len(input_seq), -1))
        return pred[-1]

model = GRU()
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
loss_function = nn.MSELoss()

#print(model)

epochs = 150

for i in range(epochs):
    for seq, labels in train_in_out_seq:
        optimizer.zero_grad()
        model.hidden_cell = (torch.zeros(1, 1, model.hidden_layer_size))
        model.hidden_cell = model.hidden_cell.squeeze(2)
        y_prediction = model(seq)

        single_loss = loss_function(y_prediction, labels)
        single_loss.backward()
        optimizer.step()

    if i%25 == 1:
        print(f'epoch: {i:3} loss: {single_loss.item():10.8f}')

print(f'epoch: {i:3} loss: {single_loss.item():10.10f}')

future_predictions = 30
test_inputs = norm_train_data[-window_size:].tolist()
#print(test_inputs)

model.eval()

for i in range(future_predictions):
    seq = torch.FloatTensor(test_inputs[-window_size:])
    with torch.no_grad():
        model.hidden = (torch.zeros(1, 1, model.hidden_layer_size))
        test_inputs.append(model(seq).item())

real_predictions = scale.inverse_transform(np.array(test_inputs[window_size:] ).reshape(-1, 1))
#print(actual_predictions)

x = np.arange(220, 250, 1)

pyplot.title('Next 30 predictions')
pyplot.ylabel('AFV')
pyplot.grid(True)
pyplot.autoscale(axis='x', tight=True)
pyplot.plot(dataset)
pyplot.plot(x,real_predictions)
pyplot.show()

pyplot.title('Next 30 predictions')
pyplot.ylabel('AFV')
pyplot.grid(True)
pyplot.autoscale(axis='x', tight=True)
pyplot.plot(dataset[-window_size:])
pyplot.plot(x,real_predictions)
pyplot.show()

acctual_AFV = sum(test_data)/30
predicted_AFV = sum(real_predictions)/30

deviation = (predicted_AFV-acctual_AFV)/acctual_AFV
print(deviation)
