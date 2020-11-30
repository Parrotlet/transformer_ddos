from Flow import *
from CONSTANTS import *


def generate_flow(packet_list,flowgap):
    packet_list.sort(key=lambda packet: packet.timestamp)
    packet_list.sort(key=lambda packet: packet.key)

    flow_list = []
    current_flow = Flow(None)
    for packet in packet_list:

        packet.frame_len = packet.min_max_normalization(packet.frame_len,Packet.max_frame_len,Packet.min_frame_len)
        packet.tcp_flags = packet.min_max_normalization(packet.tcp_flags,Packet.max_tcp_flags,Packet.min_tcp_flags)
        packet.tcp_window_size = packet.min_max_normalization(packet.tcp_window_size,Packet.max_tcp_window_size,Packet.min_tcp_window_size)
        packet.tcp_len = packet.min_max_normalization(packet.tcp_len,Packet.max_tcp_len,Packet.min_tcp_len)
        packet.tcp_ack = packet.min_max_normalization(packet.tcp_ack,Packet.max_tcp_ack,Packet.min_tcp_ack)
        packet.ip_flags_df = packet.min_max_normalization(packet.ip_flags_df,Packet.max_ip_flags_df,Packet.min_ip_flags_df)
        packet.ip_flags_mf = packet.min_max_normalization(packet.ip_flags_mf,Packet.max_ip_flags_mf,Packet.min_ip_flags_mf)
        packet.udp_len = packet.min_max_normalization(packet.udp_len,Packet.max_udp_len,Packet.min_udp_len)

        # if ip-pairs dont match or time-difference of prev and current packet greater
        # than timegap, create a new flow
        if (current_flow.key != packet.key) or ((packet.timestamp - current_flow.get_end_time()) > flowgap):
            current_flow = Flow(packet)
            flow_list.append(current_flow)
        # if not then add packet to previous flow
        else:
            current_flow.add_packet(packet)
    return flow_list


if __name__ == '__main__':
    # sem = MP.Semaphore(THREADLIMIT)
    # task = MP.Process(target=read_pcap)
    # task.start

    packet_list_ = load_list('packet_list')
    flow_list_ = generate_flow(packet_list_,FLOWGAP)
    for flow in flow_list_:
        flow.initialize_timestamp()
    save_list(flow_list_, 'flow_list')
