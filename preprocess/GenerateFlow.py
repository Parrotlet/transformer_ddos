from preprocess.Flow import *
from preprocess.CONSTANTS import *
from sklearn.preprocessing import OneHotEncoder


# generate flow depending on timestamp , and normalize features except timestamp
def generate_flow(packet_list,norm_info,flowgap):
    packet_list.sort(key=lambda packet: packet.timestamp)
    packet_list.sort(key=lambda packet: packet.key)

    enc = OneHotEncoder(sparse=False)
    enc.fit(X=[[i] for i in norm_info['highest_layer']])

    flow_list = []
    current_flow = Flow(None)
    for packet in packet_list:
        packet.highest_layer = enc.transform([[packet.highest_layer]])
        packet.frame_len = packet.min_max_normalization(packet.frame_len,norm_info['MAX_frame_len'],norm_info['MIN_frame_len'])
        packet.tcp_flags = packet.min_max_normalization(packet.tcp_flags,norm_info['MAX_tcp_flags'],norm_info['MIN_tcp_flags'])
        packet.tcp_window_size = packet.min_max_normalization(packet.tcp_window_size,norm_info['MAX_tcp_window_size'],norm_info['MIN_tcp_window_size'])
        packet.tcp_len = packet.min_max_normalization(packet.tcp_len,norm_info['MAX_tcp_len'],norm_info['MIN_tcp_len'])
        packet.tcp_ack = packet.min_max_normalization(packet.tcp_ack,norm_info['MAX_tcp_ack'],norm_info['MIN_tcp_ack'])
        packet.udp_len = packet.min_max_normalization(packet.udp_len,norm_info['MAX_udp_len'],norm_info['MIN_udp_len'])

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

    packet_list_ = load_list('../temp/packet_list')
    norm_info_ = load_list('../temp/norm_info')

    flow_list_ = generate_flow(packet_list_,norm_info_,FLOWGAP)
    save_list(flow_list_, '../temp/flow_list')