import torch
import numpy as np
import CONSTANTS
from torch.utils.data import Dataset, DataLoader
from torchvision import transforms, utils


class DDOSDataset(Dataset):

    def __init__(self, np_path):
        self.np_dataset = np.load(np_path)

    def __len__(self):
        return len(self.np_dataset)

    def __getitem__(self, idx):
        sample = self.np_dataset[idx][:,0:-1]
        label = self.np_dataset[idx][:,-1][-1]

        return sample, label
