# -------------------------------------------------------------------------------------------------------
#
# Author: Ta-Wei
# Date: 4/10/2023
# Version:
# 
# Purpose:
# (1) Scrap Datasource info from MITRE
# (2) Build the (DataSource)-(Technique) edge file
# 
import requests
from bs4 import BeautifulSoup

import itertools
from itertools import repeat
import re
import sys

import pandas as pd
import numpy as np
import scipy as sp
import matplotlib.pyplot as plt

website = 'https://attack.mitre.org/datasources/'
result = requests.get(website)
content = result.text
soup = BeautifulSoup(content, 'lxml')


tmp_link = []
for link in soup.find_all('a'):
    tmp_link.append(link.get('href'))

subs = 'datasources/D'
http_base = 'https://attack.mitre.org'
data_sub_url_path = []
full_url = []
res = [i for i in tmp_link if subs in i]
for i in res:
    data_sub_url_path.append(i)
    full_url.append(http_base+i) # full url for each group
    
data_id_lst = []
for i in data_sub_url_path:
    data_id_lst.append(list(filter(None, i.split('/')))[1])

new_data_id_lst = list(set(data_id_lst))

techniques = []
technique_m = []
techique_m_id= []

for m in full_url:
    result_m = requests.get(m)
    content_m = result_m.text
    soup_m = BeautifulSoup(content_m, 'lxml')
#    table_m = soup_m.find_all('table')
    tmp_link_m = []
    for link_m in soup_m.find_all('a'):
        tmp_link_m.append(link_m.get('href'))

    new_tmp_link_m = []
    for val in tmp_link_m:
        if val != None:
            new_tmp_link_m.append(val)            
        
    sub_m = 'techniques/T'
    technique_m = []
    technique_m_id = []
    res_m = [i for i in new_tmp_link_m if sub_m in i]
    new_res_m = list(set(res_m))
    
    for j in new_res_m:
        technique_m.append(list(filter(None, j.split('/'))))
    
    for e in technique_m:
        technique_m_id.append(e[1])
        
    new_technique_m_id = list(set(technique_m_id))
    techniques.append(new_technique_m_id)
    
data_technique = dict(zip(data_id_lst, techniques))

data_full_lst = []
technique_full_lst = []
key_lst = list(data_technique.keys())

for i in range(len(key_lst)):
    size_n = len(data_technique[key_lst[i]])
    tmp_lst = []
    tmp_lst.extend(repeat(key_lst[i], size_n))
    data_full_lst.append(tmp_lst)
    
    tmp_technique_lst = []
    tmp_technique_lst = data_technique[key_lst[i]]
    technique_full_lst.append(tmp_technique_lst)
    
new_data_full_lst = [item0 for sublist in data_full_lst for item0 in sublist]
new_technique_full_lst = [item1 for sublist in technique_full_lst for item1 in sublist]

tmp_df = pd.DataFrame(list(zip(new_data_full_lst, new_technique_full_lst)), columns=['data_source','technique'])
tmp_df.to_csv("C:/Users/c1twc/OneDrive/Documents/GitHub/MITRE-ATT-CK/data_source-technique.csv", sep=',', index=False)
