import numpy as np
from torch.utils.data import Dataset


class DDOSDataset(Dataset):

    def __init__(self, np_path):
        self.np_dataset = np.load(np_path)

    def __len__(self):
        return len(self.np_dataset)

    def __getitem__(self, idx):
        sample = self.np_dataset[idx][:,0:-1]
        label = self.np_dataset[idx][:,-1][-1]

        return sample, label
