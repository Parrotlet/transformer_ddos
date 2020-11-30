from Packet import *
# ip direction?


class Flow:
    def __init__(self, packet):
        if packet == None:
            self.ip1 = None
            self.ip2 = None
            self.key = None
            self.flow_list = []
        else:
            if packet.s_ip < packet.d_ip:
                self.ip1 = packet.s_ip
                self.ip2 = packet.d_ip
                self.key = packet.key
                self.flow_list = []
                self.add_packet(packet)
            else:
                self.ip1 = packet.d_ip
                self.ip2 = packet.s_ip
                self.key = packet.key
                self.flow_list = []
                self.add_packet(packet)

    def add_packet(self,packet):
        self.flow_list.append(packet)

    def get_end_time(self):
        return self.flow_list[-1].timestamp

    def initialize_timestamp(self):
        init_timestamp = self.flow_list[0].timestamp
        for packet in self.flow_list:
            packet.timestamp -= init_timestamp

