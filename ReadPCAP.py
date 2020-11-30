import pyshark

from CONSTANTS import *
from Packet import *


# Read pcap data and filter out logs that are not tcp or udp.Preserve features we need.
# def read_pcap(pcap_dir):
def read_pcap():
    packet_list = []
    pcap = pyshark.FileCapture('SAT-01-12-2018_0.pcap',
                               display_filter = "(ip.proto==6) or (ip.proto==17) and (!icmp)")

    for packet in pcap:
        packet = filterpcap(packet)
        Packet.highest_layers.add(packet.highest_layers)
        packet_list.append(packet)
    print('Reading pcap is done')
    Packet.max_frame_len, Packet.min_frame_len \
        = max(packet_list, key=lambda x: x.frame_len), min(packet_list, key=lambda x: x.frame_len)
    Packet.max_tcp_flags, Packet.min_tcp_flags \
        = max(packet_list, key=lambda x: x.tcp_flags), min(packet_list, key=lambda x: x.tcp_flags)
    Packet.max_tcp_window_size, Packet.min_tcp_window_size \
        = max(packet_list, key=lambda x: x.tcp_window_size), min(packet_list, key=lambda x: x.tcp_window_size)
    Packet.max_tcp_len, Packet.min_tcp_len \
        = max(packet_list, key=lambda x: x.tcp_len), min(packet_list, key=lambda x: x.tcp_len)
    Packet.max_tcp_ack, Packet.min_tcp_ack \
        = max(packet_list, key=lambda x: x.tcp_ack), min(packet_list, key=lambda x: x.tcp_ack)
    Packet.max_ip_flags_df, Packet.min_ip_flags_df \
        = max(packet_list, key=lambda x: x.ip_flags_df), min(packet_list, key=lambda x: x.ip_flags_df)
    Packet.max_ip_flags_mf, Packet.min_ip_flags_mf \
        = max(packet_list, key=lambda x: x.ip_flags_mf), min(packet_list, key=lambda x: x.ip_flags_mf)
    Packet.max_udp_len, Packet.min_udp_len \
        = max(packet_list, key=lambda x: x.udp_len), min(packet_list, key=lambda x: x.udp_len)

    return packet_list


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

    packet_list_ = read_pcap()
    save_list(packet_list_,'packet_list')