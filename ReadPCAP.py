import pyshark

from CONSTANTS import *
from Packet import *


# Read pcap data and filter out logs that are not tcp or udp.Preserve features we need.
# def read_pcap(pcap_dir):
def read_pcap(norm_info=[set()]):
    packet_list = []
    pcap = pyshark.FileCapture('SAT-01-12-2018_0.pcap',
                               display_filter="(ip.proto==6) or (ip.proto==17) and (!icmp)")
    for packet in pcap:
        packet = filterpcap(packet)
        norm_info[0].add(packet.highest_layer)
        packet_list.append(packet)
    print('Reading pcap is done')

    norm_info.append(max(packet_list, key=lambda x: x.frame_len))
    norm_info.append(max(packet_list, key=lambda x: x.tcp_flags))
    norm_info.append(max(packet_list, key=lambda x: x.tcp_window_size))
    norm_info.append(max(packet_list, key=lambda x: x.tcp_len))
    norm_info.append(max(packet_list, key=lambda x: x.tcp_ack))
    norm_info.append(max(packet_list, key=lambda x: x.ip_flags_df))
    norm_info.append(max(packet_list, key=lambda x: x.ip_flags_mf))
    norm_info.append(max(packet_list, key=lambda x: x.udp_len))

    norm_info.append(min(packet_list, key=lambda x: x.frame_len))
    norm_info.append(min(packet_list, key=lambda x: x.tcp_flags))
    norm_info.append(min(packet_list, key=lambda x: x.tcp_window_size))
    norm_info.append(min(packet_list, key=lambda x: x.tcp_len))
    norm_info.append(min(packet_list, key=lambda x: x.tcp_ack))
    norm_info.append(min(packet_list, key=lambda x: x.ip_flags_df))
    norm_info.append(min(packet_list, key=lambda x: x.ip_flags_mf))
    norm_info.append(min(packet_list, key=lambda x: x.udp_len))

    return packet_list,norm_info


def filterpcap(packet):
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
    save_list(packet_list_,'packet_list')
    save_list(norm_info_,'norm_info')
