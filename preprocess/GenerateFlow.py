from preprocess.Flow import *
from preprocess.CONSTANTS import *
from sklearn.preprocessing import OneHotEncoder


# generate flow depending on timestamp , and normalize features except timestamp
def generate_flow(packet_list,norm_info,flowgap):
    packet_list.sort(key=lambda packet: packet.timestamp)
    packet_list.sort(key=lambda packet: packet.key)

    enc = OneHotEncoder(sparse=False)
    enc.fit(X=[[i] for i in norm_info[0]])

    flow_list = []
    current_flow = Flow(None)
    for packet in packet_list:
        packet.highest_layer = enc.transform([[packet.highest_layer]])
        packet.frame_len = packet.min_max_normalization(packet.frame_len,norm_info[1],norm_info[7])
        packet.tcp_flags = packet.min_max_normalization(packet.tcp_flags,norm_info[2],norm_info[8])
        packet.tcp_window_size = packet.min_max_normalization(packet.tcp_window_size,norm_info[3],norm_info[9])
        packet.tcp_len = packet.min_max_normalization(packet.tcp_len,norm_info[4],norm_info[10])
        packet.tcp_ack = packet.min_max_normalization(packet.tcp_ack,norm_info[5],norm_info[11])
        packet.udp_len = packet.min_max_normalization(packet.udp_len,norm_info[6],norm_info[12])

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

    packet_list_ = load_list('../temp/flow_list')
    norm_info_ = load_list('../temp/norm_info')

    flow_list_ = generate_flow(packet_list_,norm_info_,FLOWGAP)
    save_list(flow_list_, '../temp/flow_list')