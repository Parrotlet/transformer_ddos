from Flow import *
from CONSTANTS import *


def generate_flow(packet_list,flowgap):
    packet_list.sort(key=lambda packet: packet.timestamp)
    packet_list.sort(key=lambda packet: packet.key)

    flow_list = []
    current_flow = Flow(None)
    for packet in packet_list:
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
