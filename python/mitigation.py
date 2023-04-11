# ---------------------------------------------------------------------------------------------------------------
#
# Author: Ta-Wei
# Date: March 2023
# Version:
#
# Purpose:
# (1) Extract mitigation info from MITRE
# (2) Build the edge file for (Mitigation) and (Technique)
#
# ----------------------------------------------------------------------------------------------------------------
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

website = 'https://attack.mitre.org/mitigations/enterprise/'
result = requests.get(website)
content = result.text
soup = BeautifulSoup(content, 'lxml')

#print(soup.prettify())
tmp_link = []
for link in soup.find_all('a'):
    tmp_link.append(link.get('href'))
    
# Extract the sub url_path of each mitigation ID --> mitigation_sub_url_path
# Create a full url path for each mitigation ID --> full_url 
subs = 'mitigations/M'
http_base = 'https://attack.mitre.org/'
mitigation_sub_url_path = []
full_url = []
res = [i for i in tmp_link if subs in i]
for i in res:
    mitigation_sub_url_path.append(i)
    full_url.append(http_base+i)
    
# Create a list containing the mitigation IDs    
mitigation_id_lst = []
for i in mitigation_sub_url_path:
    mitigation_id_lst.append(list(filter(None, i.split('/')))[1])
    
techniques = []
for m in full_url:
    result_m = requests.get(m)
    content_m = result_m.text
    soup_m = BeautifulSoup(content_m, 'lxml')
    table_m = soup_m.find_all('table')
    tmp_link_m = []
    for link_m in soup_m.find_all('a'):
        tmp_link_m.append(link_m.get('href'))
        
    sub_m = 'techniques/T'
    mitigation_m = []
    mitigation_m_id = []
    res_m = [i for i in tmp_link_m if sub_m in i]
    new_res_m = list(set(res_m))
    
    for j in new_res_m:
        mitigation_m.append(list(filter(None, j.split('/'))))
    
    for e in mitigation_m:
        mitigation_m_id.append(e[1])
        
    new_mitigation_m_id = list(set(mitigation_m_id))
    techniques.append(new_mitigation_m_id)
    
mitigation_technique = dict(zip(mitigation_id_lst, techniques))

len(mitigation_technique['M1036'])
mitigation_full_lst =[]
technique_full_lst = []

key_lst = list(mitigation_technique.keys())

for i in range(len(key_lst)):
# replicate the mitigation ID size_n times based on the total number of relevant techniques it mitigates
# mitigation_full_lst is a list of list; needs to be flattened later
    size_n = len(mitigation_technique[key_lst[i]])
    tmp_lst = []
    tmp_lst.extend(repeat(key_lst[i], size_n))
    mitigation_full_lst.append(tmp_lst)

# Extract techniques related to a given mitigation ID
# technique_full_lst is a list of list; needs to be flatten later
    tmp_technique_lst = []
    tmp_technique_lst = mitigation_technique[key_lst[i]]
    technique_full_lst.append(tmp_technique_lst)

new_mitigation_full_lst = [item0 for sublist in mitigation_full_lst for item0 in sublist]
new_technique_full_lst = [item1 for sublist in technique_full_lst for item1 in sublist]

# Create a Pandas DataFrtmp_df.to_csv("C:/Users/c1twc/OneDrive/Documents/GitHub/MITRE-ATT-CK/mitigation-technique.csv", sep=',', index=False)ame by combining new_mitigation_full_lst & new_technique_full_lst
tmp_df = pd.DataFrame(list(zip(new_mitigation_full_lst, new_te

# convert & output Pandas DataFrame to a CSV file
tmp_df.to_csv("C:/Users/c1twc/OneDrive/Documents/GitHub/MITRE-ATT-CK/mitigation-technique.csv", sep=',', index=False)
