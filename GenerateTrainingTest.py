from Flow import *
from CONSTANTS import *
# data normalization ---> pytorch dataset


if __name__ == '__main__':
    # sem = MP.Semaphore(THREADLIMIT)
    # task = MP.Process(target=read_pcap)
    # task.start

    flow_list_ = load_list('flow_list')