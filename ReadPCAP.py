import pyshark
import time
from CONSTANTS import *
from Packet import *


# Read pcap data and filter out logs that are not tcp or udp. Preserve features we need.
# def read_pcap(pcap_dir):
def read_pcap(norm_info=[set()]):
    packet_list = []
    pcap = pyshark.FileCapture('pcap/01-12/PCAP-01-12_0-0249/SAT-01-12-2018_0',
                               display_filter="(ip.proto==6) or (ip.proto==17) and (!icmp)")
    filter_start_time = time.time()
    for packet in pcap:
        packet = filter_pcap(packet)
        norm_info[0].add(packet.highest_layer)
        packet_list.append(packet)
    filter_end_time = time.time()
    print('Reading pcap is done')
    print('Reading time is',filter_end_time-filter_start_time)


    # get normalization info
    # norm_info.append(max(x.frame_len for x in packet_list))

    norm_info.append(max(packet_list, key=lambda x: x.frame_len).frame_len)
    norm_info.append(max(packet_list, key=lambda x: x.tcp_flags).tcp_flags)
    norm_info.append(max(packet_list, key=lambda x: x.tcp_window_size).tcp_window_size)
    norm_info.append(max(packet_list, key=lambda x: x.tcp_len).tcp_len)
    norm_info.append(max(packet_list, key=lambda x: x.tcp_ack).tcp_ack)
    norm_info.append(max(packet_list, key=lambda x: x.udp_len).udp_len)

    norm_info.append(min(packet_list, key=lambda x: x.frame_len).frame_len)
    norm_info.append(min(packet_list, key=lambda x: x.tcp_flags).tcp_flags)
    norm_info.append(min(packet_list, key=lambda x: x.tcp_window_size).tcp_window_size)
    norm_info.append(min(packet_list, key=lambda x: x.tcp_len).tcp_len)
    norm_info.append(min(packet_list, key=lambda x: x.tcp_ack).tcp_ack)
    norm_info.append(min(packet_list, key=lambda x: x.udp_len).udp_len)

    norm_info.append(len(norm_info[0]))
    norm_end_time = time.time()
    print('getting normalization info is done ')
    print('normalization time',norm_end_time-filter_end_time)
    return packet_list,norm_info


def filter_pcap(packet):
    s_ip = packet.ip.src
    d_ip = packet.ip.dst
    ip_flags = packet.ip.flags

    timestamp = packet.frame_info.time_epoch
    frame_len = packet.frame_info.len
    highest_layer = packet.highest_layer

    # source = socket.inet_aton(s_ip)
    # dest = socket.inet_aton(d_ip)
    # if source < dest:
    #     key = source + dest
    # else:
    #     key = dest + source
    if (packet.ip.proto == '6'):
        # s_port = packet.tcp.srcport
        # d_port = packet.tcp.dstport
        udp_len = 0
        tcp_flags = packet.tcp.flags
        tcp_window_size = packet.tcp.window_size
        tcp_len = packet.tcp.len
        tcp_ack = packet.tcp.ack
    else:
        try:
            # s_port = packet.udp.srcport
            # d_port = packet.udp.dstport
            udp_len = packet.udp.length
            tcp_flags, tcp_window_size, tcp_len, tcp_ack = 0, 0, 0, 0

        except:
            print(packet)
    p = Packet([s_ip, d_ip, timestamp, frame_len, highest_layer,
                tcp_flags, tcp_window_size, tcp_len, tcp_ack, ip_flags, udp_len])
    return p


# def min_max(li,packet_attribute):
#     # max_value = lambda value,max_value : value if value > max_value else max_value
#     # min_value = lambda value,min_value : value if value < min_value else min_value
#
#     max_value = max(value,max_value)
#     min_value = min(value,min_value)
#     return max_value,min_value


if __name__ == '__main__':
    # sem = MP.Semaphore(THREADLIMIT)
    # task = MP.Process(target=read_pcap)
    # task.start

    packet_list_,norm_info_ = read_pcap()
    save_list(packet_list_,'temp/packet_list')
    save_list(norm_info_,'temp/norm_info')
