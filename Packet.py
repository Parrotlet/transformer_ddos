import socket

# ip direction?
# defines properties of a packet
class Packet:
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
            self.ip_flags_mf = str(bin(int(fields[9],16)))[3]

            self.udp_len = int(fields[10]) # max = 576

            if self.s_ip < self.d_ip:
                self.key = self.s_ip + self.d_ip
            else:
                self.key = self.d_ip + self.s_ip

'''   def min_max_normalization(self, value, max_value, min_value=0):
        if value > max_value or value < min_value:
            print('-----')
            print(value)
        value = (value - min_value)/(max_value-min_value)
        return value

    def check(self,value,v):
        if value > 1 or value < 0:
            print(v)
            print('_____')'''
