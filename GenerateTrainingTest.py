import numpy as np
from math import ceil,floor
from Flow import *
from CONSTANTS import *


# data normalization ---> pytorch dataset


def flow_to_numpy(flow_list,dim_num):

    for flow in flow_list:
        label_ = lambda x:1 if (flow.flow_list[0].s_ip == b'\xac\x10\x00\x05'
                               or flow.flow_list[0].d_ip == b'\xac\x10\x00\x05') else 0
        flow.initialize_timestamp()
        sample_num = ceil(flow.get_end_time() / WINDOW_TIME)
        assign_table = [0 for i in range(sample_num)]
        samples_list = []
        samples_list.extend([np.zeros((WINDOW_PACKET_NUMBER,dim_num)) for i in range(sample_num)])
        for packet in flow:
            a = floor(packet.timestamp / WINDOW_TIME)
            packet_np = packet_to_np(packet,label_)
            samples_list[a][assign_table[a]] = packet_np
            assign_table[a]+=1

# packet ---> np array [feature1,.........,label]
def packet_to_np(packet,label):
    features_list = []
    features_list.extend([packet.timestamp,packet.frame_len,packet.tcp_flags,packet.tcp_window_size,packet.tcp_len,
                          packet.tcp_ack,packet.ip_flags_df,packet.ip_flags_mf,packet.udp_len,label])
    features_np = np.asarray([features_list])
    np.insert(features_np,-1,packet.highest_layer[0],axis=0)
    return features_np


if __name__ == '__main__':
    # sem = MP.Semaphore(THREADLIMIT)
    # task = MP.Process(target=read_pcap)
    # task.start

    flow_list_ = load_list('flow_list')
    dim_num_ = load_list('norm_info')[-1] + FEATURE_NUM
