import pyshark
import pandas as pd
import socket
from CONSTANTS import *
import multiprocessing as MP


def read_label_csv(dir_path, filename, filter_=False):
    # read csv to df    Source IP,Source Port,Destination IP,Destination Port,Protocol,Timestamp,Flow Duration,answer
    label_df = pd.concat([pd.read_csv(dir_path+f, usecols=[2, 3, 4, 5, 6, 7, 8, 9, 10, 87], header=0,
                                names=['s_ip', 's_port', 'd_ip', 'd_port', 'protocol', 'timestamp', 'flow_duration',
                                       'total_fwd', 'total_bwd','label']
                                     , low_memory=False, parse_dates=['timestamp']) for f in filename])
    if filter_==True:
        # filter parameters
        flow_duration_min = 1
        total_packet_num = 0
        # filter data
        label_df = label_df[((label_df['flow_duration'] > (flow_duration_min*1000000)) &
                         ((label_df['total_fwd']+label_df['total_bwd']) > total_packet_num))]
    # add end_timestamp
    label_df.loc[:, 'end_timestamp'] = label_df.loc[:, 'timestamp']+pd.to_timedelta(label_df.loc[:, 'flow_duration']
                                                                                , unit='micro')
    # drop columns
    label_df.drop(columns=['total_fwd', 'total_bwd', 'flow_duration'])
    # reorder column order
    label_df = label_df[['s_ip', 's_port', 'd_ip', 'd_port', 'protocol', 'timestamp',  'end_timestamp', 'label']]
    # save df
    label_df.to_pickle('label_df')

    # csv.iloc[:5000].to_csv("NTP5000.csv")
    return label_df


# Read pcap data and filter out logs that are not tcp or udp.Preserve features we need.
# def read_pcap(pcap_dir):
def read_pcap():
    pcap_df = pd.DataFrame(columns=['s_ip', 's_port', 'd_ip', 'd_port', 'timestamp', 'frame_len', 'highest_layer',
                                    'tcp_flags', 'tcp_window_size', 'tcp_len', 'tcp_ack',
                                    'ip_flags', 'udp_len'])

    pcap = pyshark.FileCapture('pcap/01-12/PCAP-01-12_0-0249/SAT-01-12-2018_0',
                               display_filter = "(ip.proto==6) or (ip.proto==17) and (!icmp)")
    for packet in pcap:
        s_ip = packet.ip.src
        d_ip = packet.ip.dst
        ip_flags = packet.ip.flags

        timestamp = packet.frame_info.time
        frame_len = packet.frame_info.len
        highest_layer = packet.highest_layer

        source = socket.inet_aton(s_ip)
        dest = socket.inet_aton(d_ip)
        if source < dest:
            key = source + dest
        else:
            key = dest + source

        if (packet.ip.proto=='6'):
            s_port = packet.tcp.srcport
            d_port = packet.tcp.dstport
            udp_len = '0'
            tcp_flags = packet.tcp.flags
            tcp_window_size = packet.tcp.window_size
            tcp_len = packet.tcp.len
            tcp_ack = packet.tcp.ack
        else:
            try:
                s_port = packet.udp.srcport
                d_port = packet.udp.dstport
                udp_len = packet.udp.length
                tcp_flags, tcp_window_size, tcp_len, tcp_ack = '0', '0', '0', '0'

            except:
                print('hi')

        pcap_df = pcap_df.append({'key':key,'s_ip':s_ip, 's_port':s_port, 'd_ip':d_ip, 'd_port':d_port, 'timestamp':timestamp
                           , 'frame_len':frame_len, 'highest_layer':highest_layer,'tcp_flags':tcp_flags
                           , 'tcp_window_size':tcp_window_size, 'tcp_len':tcp_len, 'tcp_ack':tcp_ack
                           , 'ip_flags':ip_flags, 'udp_len':udp_len},ignore_index=True)
    return pcap_df



if __name__ == '__main__':
    label_df = read_label_csv(csv_path_1, csv_list_1)
    # pcap_df = read_pcap()
    # print('read ok')
    # pcap_df.to_pickle('pcap_df1')

    # print(label_df[(label_df['label'] == 'BENIGN')])
    # print(label_df[((label_df['s_ip'] == '172.16.0.5') | (label_df['d_ip'] == '172.16.0.5')) ])

    print(label_df[(((label_df['s_ip'] == '172.16.0.5') | (label_df['d_ip'] == '172.16.0.5')) & (label_df['label'] == 'BENIGN'))])