# ---------------------------------------------------------------------------------------------------------------
#
# Author: Ta-Wei
# Date: March 2023
# Version:
#
# Purpose:
# (1) Extract actor group info from MITRE
# (2) Build the edge file for (Group) and (Technique)
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

website = 'https://attack.mitre.org/groups/'
result = requests.get(website)
content = result.text
soup = BeautifulSoup(content, 'lxml')

tmp_link = []
for link in soup.find_all('a'):
    tmp_link.append(link.get('href'))

subs = 'groups/G'
http_base = 'https://attack.mitre.org/'
group_sub_url_path = []
full_url = []
res = [i for i in tmp_link if subs in i]
for i in res:
    group_sub_url_path.append(i)
    full_url.append(http_base+i) # full url for each group
    
group_id_lst = []
for i in group_sub_url_path:
    group_id_lst.append(list(filter(None, i.split('/')))[1])
    
techniques = []
for g in full_url:
    result_g = requests.get(g)
    content_g = result_g.text
    soup_g = BeautifulSoup(content_g, 'lxml')
    table_g = soup_g.find_all('table')
    tmp_link_g = []
    for link_g in soup_g.find_all('a'):
        tmp_link_g.append(link_g.get('href'))
        
    sub_g = 'techniques/T'
    group_g = []
    group_g_id = []
    res_g = [i for i in tmp_link_g if sub_g in i]
    new_res_g = list(set(res_g))
    
    for j in new_res_g:
        group_g.append(list(filter(None, j.split('/'))))
        
    for e in group_g:
        group_g_id.append(e[1])
        
    new_group_g_id = list(set(group_g_id))
    techniques.append(new_group_g_id)

# Create a dictionary where 'key' is the Group id and 'value' a list of attack techniques
group_technique = dict(zip(group_id_lst, techniques))

group_full_lst =[]
technique_full_lst = []

key_lst = list(group_technique.keys())

for i in range(len(key_lst)):
# replicate the mitigation ID size_n times based on the total number of relevant techniques it mitigates
# mitigation_full_lst is a list of list; needs to be flattened later
    size_n = len(group_technique[key_lst[i]])
    tmp_lst = []
    tmp_lst.extend(repeat(key_lst[i], size_n))
    group_full_lst.append(tmp_lst)

# Extract techniques related to a given mitigation ID
# technique_full_lst is a list of list; needs to be flatten later
    tmp_technique_lst = []
    tmp_technique_lst = group_technique[key_lst[i]]
    technique_full_lst.append(tmp_technique_lst)

new_group_full_lst = [item0 for sublist in group_full_lst for item0 in sublist]
new_technique_full_lst = [item1 for sublist in technique_full_lst for item1 in sublist]


# Create a Pandas DataFrame by combining new_mitigation_full_lst & new_technique_full_lst
tmp_df = pd.DataFrame(list(zip(new_group_full_lst, new_technique_full_lst)), columns=['group','technique'])


tmp_df.to_csv("C:/Users/c1twc/OneDrive/Documents/GitHub/MITRE-ATT-CK/group-technique.csv", sep=',', index=False)
