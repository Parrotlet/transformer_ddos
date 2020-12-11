import pyshark
import time
import concurrent.futures
import datetime
from datetime import datetime as dt
from preprocess.CONSTANTS import *
from preprocess.Packet import *


# Read pcap data and filter out logs that are not tcp or udp. Preserve features we need.
# def read_pcap(pcap_dir):
def read_pcap(pcap_path,norm_info):
    packet_list = []
    print(pcap_path)
    pcap = pyshark.FileCapture(pcap_path, display_filter="(ip.proto==6) or (ip.proto==17) and (!icmp)")
    filter_start_time = time.time()
    for packet in pcap:
        if dt.strptime(str(pcap[0].frame_info.time)[:21], '%b  %d, %Y %H:%M:%S')\
                >(dt.strptime(DDOS_START_TIME_1['DrDoS_DNS'][:19], '%Y-%m-%d %H:%M:%S') + datetime.timedelta(hours = 12)):
            print(pcap_path,'exit')
            exit()
        packet = filter_pcap(packet)
        norm_info['highest_layer'].add(packet.highest_layer)
        packet_list.append(packet)
    filter_end_time = time.time()
    print('Reading',pcap_path,'is done')
    print('Reading ',pcap_path,'time is',filter_end_time-filter_start_time)

    norm_info['MAX_frame_len'] = max(packet_list, key=lambda x: x.frame_len).frame_len
    norm_info['MAX_tcp_flags'] = max(packet_list, key=lambda x: x.tcp_flags).tcp_flags
    norm_info['MAX_tcp_window_size'] = max(packet_list, key=lambda x: x.tcp_window_size).tcp_window_size
    norm_info['MAX_tcp_len'] = max(packet_list, key=lambda x: x.tcp_len).tcp_len
    norm_info['MAX_tcp_ack'] = max(packet_list, key=lambda x: x.tcp_ack).tcp_ack
    norm_info['MAX_udp_len'] = max(packet_list, key=lambda x: x.udp_len).udp_len

    norm_info['MIN_frame_len'] = min(packet_list, key=lambda x: x.frame_len).frame_len
    norm_info['MIN_tcp_flags'] = min(packet_list, key=lambda x: x.tcp_flags).tcp_flags
    norm_info['MIN_tcp_window_size'] = min(packet_list, key=lambda x: x.tcp_window_size).tcp_window_size
    norm_info['MIN_tcp_len'] = min(packet_list, key=lambda x: x.tcp_len).tcp_len
    norm_info['MIN_tcp_ack'] = min(packet_list, key=lambda x: x.tcp_ack).tcp_ack
    norm_info['MIN_udp_len'] = min(packet_list, key=lambda x: x.udp_len).udp_len
    # norm_info['MAX_frame_len'] = max(norm_info['MAX_frame_len'],max(packet_list, key=lambda x: x.frame_len).frame_len)
    # norm_info['MAX_tcp_flags'] = max(norm_info['MAX_tcp_flags'],max(packet_list, key=lambda x: x.tcp_flags).tcp_flags)
    # norm_info['MAX_tcp_window_size'] = max(norm_info['MAX_tcp_window_size'],max(packet_list, key=lambda x: x.tcp_window_size).tcp_window_size)
    # norm_info['MAX_tcp_len'] = max(norm_info['MAX_tcp_len'],max(packet_list, key=lambda x: x.tcp_len).tcp_len)
    # norm_info['MAX_tcp_ack'] = max(norm_info['MAX_tcp_ack'],max(packet_list, key=lambda x: x.tcp_ack).tcp_ack)
    # norm_info['MAX_udp_len'] = max(norm_info['MAX_udp_len'],max(packet_list, key=lambda x: x.udp_len).udp_len)
    #
    # norm_info['MIN_frame_len'] = min(norm_info['MIN_frame_len'],min(packet_list, key=lambda x: x.frame_len).frame_len)
    # norm_info['MIN_tcp_flags'] = min(norm_info['MIN_tcp_flags'],min(packet_list, key=lambda x: x.tcp_flags).tcp_flags)
    # norm_info['MIN_tcp_window_size'] = min(norm_info['MIN_tcp_window_size'],min(packet_list, key=lambda x: x.tcp_window_size).tcp_window_size)
    # norm_info['MIN_tcp_len'] = min(norm_info['MIN_tcp_len'],min(packet_list, key=lambda x: x.tcp_len).tcp_len)
    # norm_info['MIN_tcp_ack'] = min(norm_info['MIN_tcp_ack'],min(packet_list, key=lambda x: x.tcp_ack).tcp_ack)
    # norm_info['MIN_udp_len'] = min(norm_info['MIN_udp_len'],min(packet_list, key=lambda x: x.udp_len).udp_len)
    # get normalization info
    # norm_info.append(max(x.frame_len for x in packet_list))

    # norm_info.append(max(packet_list, key=lambda x: x.frame_len).frame_len)
    # norm_info.append(max(packet_list, key=lambda x: x.tcp_flags).tcp_flags)
    # norm_info.append(max(packet_list, key=lambda x: x.tcp_window_size).tcp_window_size)
    # norm_info.append(max(packet_list, key=lambda x: x.tcp_len).tcp_len)
    # norm_info.append(max(packet_list, key=lambda x: x.tcp_ack).tcp_ack)
    # norm_info.append(max(packet_list, key=lambda x: x.udp_len).udp_len)
    #
    # norm_info.append(min(packet_list, key=lambda x: x.frame_len).frame_len)
    # norm_info.append(min(packet_list, key=lambda x: x.tcp_flags).tcp_flags)
    # norm_info.append(min(packet_list, key=lambda x: x.tcp_window_size).tcp_window_size)
    # norm_info.append(min(packet_list, key=lambda x: x.tcp_len).tcp_len)
    # norm_info.append(min(packet_list, key=lambda x: x.tcp_ack).tcp_ack)
    # norm_info.append(min(packet_list, key=lambda x: x.udp_len).udp_len)

    norm_end_time = time.time()
    print(pcap_path,'normalization time',norm_end_time-filter_end_time)
    return packet_list,norm_info


def filter_pcap(packet):
    # s_ip = packet.ip.src
    # d_ip = packet.ip.dst
    # ip_flags = packet.ip.flags
    #
    # timestamp = packet.frame_info.time_epoch
    # frame_len = packet.frame_info.len
    # highest_layer = packet.highest_layer

    # source = socket.inet_aton(s_ip)
    # dest = socket.inet_aton(d_ip)
    # if source < dest:
    #     key = source + dest
    # else:
    #     key = dest + source
    if packet.ip.proto == '6':
        # s_port = packet.tcp.srcport
        # d_port = packet.tcp.dstport
        udp_len = 0
        tcp_flags = packet.tcp.flags
        tcp_window_size = packet.tcp.window_size
        tcp_len = packet.tcp.len
        tcp_ack = packet.tcp.ack
    else:
        udp_len = packet.udp.length
        tcp_flags, tcp_window_size, tcp_len, tcp_ack = 0, 0, 0, 0

    return Packet([packet.ip.src, packet.ip.dst, packet.frame_info.time_epoch, packet.frame_info.len,
                   packet.highest_layer, tcp_flags, tcp_window_size, tcp_len, tcp_ack, packet.ip.flags, udp_len])


# mode=0,return 01-12
def get_pcap_name(num_start,num_end,mode=0):
    if mode == 0:
        return ['../pcap/01-12/PCAP-01-12_0-0249/SAT-01-12-2018_0'+str(i) for i in range(num_start,num_end+1)]
    return ['../pcap/03-11/PCAP-03-11/SAT-03-11-2018_0'+str(i) for i in range(num_start,num_end+1)]
# def min_max(li,packet_attribute):
#     # max_value = lambda value,max_value : value if value > max_value else max_value
#     # min_value = lambda value,min_value : value if value < min_value else min_value
#
#     max_value = max(value,max_value)
#     min_value = min(value,min_value)
#     return max_value,min_value


if __name__ == '__main__':
    raw_pcap = get_pcap_name(1, 3)
    # print(raw_pcap)
    with concurrent.futures.ProcessPoolExecutor(max_workers=16) as executor:
        result = executor.map(read_pcap,raw_pcap,[INIT_NORM_INFO for _ in range(len(raw_pcap))])

