import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim

torch.manual_seed(1)
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

class LSTM(nn.Module):

    def __init__(self,feature_dim, hidden_dim):
        super(LSTM, self).__init__()
        self.lstm = nn.LSTM(feature_dim, hidden_dim,batch_first=True)
        self.hidden2label = nn.Linear(hidden_dim, 1)

    def forward(self, x):
        lstm_out, _ = self.lstm(x)
        # x 的 dimension (batch, seq_len, hidden_size)
        # 取用 LSTM 最後一層的 hidden state
        out = self.hidden2label(lstm_out[:, -1, :])
        return out


if __name__ == '__main__':

