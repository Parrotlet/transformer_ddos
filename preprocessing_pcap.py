import pyshark
import pandas as pd


def read_csv(dir_path,filename):
    #   Source Port,Destination IP,Destination Port,Protocol,Timestamp,Flow Duration,answer
    csv = pd.concat([pd.read_csv(dir_path+f,usecols=[2,3,4,5,6,7,87],low_memory=False) for f in filename])
    csv.to_csv('label.csv')

    '''for file in filename:
        temp = pd.read_csv(dir_path+filename,usecols=[2,3,4,5,6,7,87],low_memory=False)
    '''
        # csv.iloc[:5000].to_csv("NTP5000.csv")
        # cap = pyshark.FileCapture('pcap/SAT-01-12-2018_0')
    return csv


'''def read_pcap(dir_path,filename):
    for file in dir_path:
        pcap'''


if __name__ == '__main__':
    csv_path_1 = 'csv/01-12/'
    csv_list_1 = ['DrDoS_NTP.csv','DrDoS_DNS.csv','DrDoS_LDAP.csv','DrDoS_MSSQL.csv','DrDoS_NetBIOS.csv',
                  'DrDoS_SNMP.csv','DrDoS_SSDP.csv','DrDoS_UDP.csv','UDPLag.csv','Syn.csv','TFTP.csv']
    dir_path_1 = ['pcap/01-12/PCAP-01-12_0-0249', 'pcap/01-12/PCAP-01-12_0250-0499',
                  'pcap/01-12/PCAP-01-12_0500-0749', 'pcap/01-12/PCAP-01-12_0750-0818']

    # csv = read_csv(csv_path_1,csv_list_1)
    csv = pd.read_csv('label.csv',chunksize=100000)