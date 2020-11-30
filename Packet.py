import socket

# ip direction?
# defines properties of a packet
class Packet:
    max_frame_len,min_frame_len,max_tcp_flags,min_tcp_flags = 0
    max_tcp_window_size,min_tcp_window_size,max_tcp_len,min_tcp_len = 0
    max_tcp_ack ,min_tcp_ack ,max_ip_flags_df,min_ip_flags_df = 0
    max_ip_flags_mf,min_ip_flags_mf,max_udp_len,min_udp_len = 0
    highest_layers = set()
    def __init__(self, fields):
        if fields == None:
            self.s_ip = None
            # self.s_port = None
            self.d_ip = None
            # self.d_port = None
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
            # self.s_port = int(fields[1]) # one hot encoding
            self.d_ip = socket.inet_aton(fields[1])
            # self.d_port = int(fields[3]) # one hot encoding
            self.timestamp = float(fields[2]) # max=100 min=0

            self.frame_len = int(fields[3])# max=1500 or 576? min=0

            self.highest_layer = str(fields[4]) # one hot encoding

            self.tcp_flags = int(str(fields[5]),16) # max = 2 ^ 9 -1 =511

            self.tcp_window_size = int(fields[6]),65535 # max = 65535

            self.tcp_len = int(fields[7])# max = 576

            self.tcp_ack = int(fields[8])# max = 65536

            self.ip_flags_df = str(bin(int(fields[9],16)))[2]
            if int(fields[9],16) == 0:
                self.ip_flags_mf = 0
            else:
                self.ip_flags_mf = str(bin(int(fields[9],16)))[3]

            self.udp_len = int(fields[10]) # max = 576

            if self.s_ip < self.d_ip:
                self.key = self.s_ip + self.d_ip
            else:
                self.key = self.d_ip + self.s_ip

    @staticmethod
    def min_max_normalization(value, max_value, min_value):
        value = (value - min_value)/(max_value-min_value)
        return value
    #
    # def check(self,value,v):
    #     if value > 1 or value < 0:
    #         print(v)
    #         print('_____')


# class NormalizationInfo:
#     max_frame_len,min_frame_len,max_tcp_flags,min_tcp_flags = 0
#     max_tcp_window_size,min_tcp_window_size,max_tcp_len,min_tcp_len = 0
#     max_tcp_ack ,min_tcp_ack ,max_ip_flags_df,min_ip_flags_df = 0
#     max_ip_flags_mf,min_ip_flags_mf,max_udp_len,min_udp_len = 0

