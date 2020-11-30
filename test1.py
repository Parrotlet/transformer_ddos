import pandas as pd
import numpy as np
pcap_df = pd.read_pickle('pcap_df1')
label_df = pd.read_pickle('label_df')
# print(label_df[(label_df['label'] == 'BENIGN')])
#
# print(label_df[((label_df['s_ip'] == '172.16.0.5') | (label_df['d_ip'] == '172.16.0.5')) ])

print(label_df[(((label_df['s_ip'] == '172.16.0.5') | (label_df['d_ip'] == '172.16.0.5')) & (label_df['label'] == 'BENIGN'))])