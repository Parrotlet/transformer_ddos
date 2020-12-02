import pickle

CSV_PATH_1 = 'csv/01-12/'
# csv_list_1 = ['DrDoS_NTP.csv','DrDoS_DNS.csv','DrDoS_LDAP.csv','DrDoS_MSSQL.csv','DrDoS_NetBIOS.csv',
#               'DrDoS_SNMP.csv','DrDoS_SSDP.csv','DrDoS_UDP.csv','UDPLag.csv','Syn.csv','TFTP.csv']
CSV_LIST_1 = ['DrDoS_NTP.csv']
PCAP_DIR_PATH_1 = ['pcap/01-12/PCAP-01-12_0-0249', 'pcap/01-12/PCAP-01-12_0250-0499',
                  'pcap/01-12/PCAP-01-12_0500-0749', 'pcap/01-12/PCAP-01-12_0750-0818']
ATTACKER_IP = ['172.16.0.5']
VICTIM_IP_TRAING = ['192.168.50.1', '192.168.50.5', '192.168.50.6', '192.168.50.7', '192.168.50.8', '205.174.165.81']
VICTIM_IP_TEST = ['192.168.50.4', '192.168.50.6', '192.168.50.7', '192.168.50.8', '192.168.50.9', '205.174.165.81']
THREADLIMIT = 10
# unit:second
FLOWGAP = 600
WINDOW_TIME = 100
WINDOW_PACKET_NUMBER = 100
# exclude highest layer
FEATURE_NUM = 10


def save_list(l,f_name):
    with open(f_name, "wb") as fp:
        pickle.dump(l, fp)


def load_list(f_name):
    with open(f_name, "rb") as fp:
        l = pickle.load(fp)
    return l

