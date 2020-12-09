import pickle

CSV_PATH_1 = '../csv/01-12/'
CSV_PATH_2 = '../csv/03-11/'
# csv_list_1 = ['DrDoS_NTP.csv','DrDoS_DNS.csv','DrDoS_LDAP.csv','DrDoS_MSSQL.csv','DrDoS_NetBIOS.csv',
#               'DrDoS_SNMP.csv','DrDoS_SSDP.csv','DrDoS_UDP.csv','UDPLag.csv','Syn.csv','TFTP.csv']
PCAP_DIR_PATH_1 = ['../pcap/01-12/PCAP-01-12_0-0249', '../pcap/01-12/PCAP-01-12_0250-0499',
                  '../pcap/01-12/PCAP-01-12_0500-0749', '../pcap/01-12/PCAP-01-12_0750-0818']
PCAP_DIR_PATH_2 = ['../pcap/03-11/PCAP-03-11']
DDOS_START_TIME_1 = {'Syn': '2018-12-01 13:30:30.741451', 'TFTP': '2018-12-01 13:34:27.403713',
                   'DrDoS_MSSQL': '2018-12-01 11:32:32.915441', 'DrDoS_DNS': '2018-12-01 10:51:39.813448',
                   'DrDoS_NTP': '2018-12-01 09:17:11.183810', 'UDPLag': '2018-12-01 13:04:45.928673',
                   'DrDoS_SSDP': '2018-12-01 12:23:13.663425', 'DrDoS_LDAP': '2018-12-01 11:22:40.254769',
                   'DrDoS_NetBIOS': '2018-12-01 11:47:08.463789', 'DrDoS_UDP': '2018-12-01 12:36:57.628026',
                   'DrDoS_SNMP': '2018-12-01 12:00:13.902782'}
DDOS_START_TIME_2 = {'Syn': '2018-11-03 11:36:28.607338', 'LDAP': '2018-11-03 10:09:00.565557',
                     'UDPLag': '2018-11-03 11:01:43.652742', 'NetBIOS': '2018-11-03 10:01:48.920574',
                     'MSSQL': '2018-11-03 10:29:52.072724', 'UDP': '2018-11-03 10:42:57.176671',
                     'Portmap': '2018-11-03 09:18:16.964447'}
ATTACKER_IP = ['172.16.0.5']
VICTIM_IP_TRAING = ['192.168.50.1', '192.168.50.5', '192.168.50.6', '192.168.50.7', '192.168.50.8', '205.174.165.81']
VICTIM_IP_TEST = ['192.168.50.4', '192.168.50.6', '192.168.50.7', '192.168.50.8', '192.168.50.9', '205.174.165.81']
INIT_NORM_INFO = {'highest_layer': set(),'MAX_frame_len':0,'MAX_tcp_flags':0,'MAX_tcp_window_size':0,
                  'MAX_tcp_len':0,'MAX_tcp_ack':0,'MAX_udp_len':0,'MIN_frame_len':0,'MIN_tcp_flags':0,
                  'MIN_tcp_window_size':0,'MIN_tcp_len':0,'MIN_tcp_ack':0,'MIN_udp_len':0}
THREADLIMIT = 10
FLOWGAP = 600  # unit:second
WINDOW_TIME = 100
WINDOW_PACKET_NUMBER = 100
FEATURE_NUM = 10  # exclude highest layer


def save_list(l,f_name):
    with open(f_name, "wb") as fp:
        pickle.dump(l, fp)


def load_list(f_name):
    with open(f_name, "rb") as fp:
        return pickle.load(fp)

