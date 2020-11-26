import socket

# ip direction?
# defines properties of a packet
class Packet:
    def __init__(self, fields):
        if fields == None:
            self.s_ip = None
            self.s_port = None
            self.d_ip = None
            self.d_port = None
            self.timestamp = None
            self.frame_len = 0
            self.highest_layer = None
            self.tcp_flags = None
            self.tcp_window_size = None
            self.tcp_len = None
            self.tcp_ack = None
            self.ip_flags = None
            self.udp_len = None
            self.key = None
        else:
            self.s_ip = socket.inet_aton(fields[0])
            self.s_port = int(fields[1])
            self.d_ip = socket.inet_aton(fields[2])
            self.d_port = int(fields[3])
            self.timestamp = float(fields[4])
            self.frame_len = int(fields[5])
            self.highest_layer = str(fields[6])
            self.tcp_flags = int(str(fields[7]),16)
            self.tcp_window_size = int(fields[8])
            self.tcp_len = int(fields[9])
            self.tcp_ack = int(fields[10])
            self.ip_flags = int(str(fields[11]),16)

            self.udp_len = int(fields[12])
            if self.s_ip < self.d_ip:
                self.key = self.s_ip + self.d_ip
            else:
                self.key = self.d_ip + self.s_ip

