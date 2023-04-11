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

technique = []
technique_m = []
technique_id_m = []
m = 'https://attack.mitre.org/datasources/DS0026/'
result_m = requests.get(m)
content_m = result_m.text
soup_m = BeautifulSoup(content_m, 'lxml')
table_m = soup_m.find_all('table')
tmp_link_m = []
for link_m in soup_m.find_all('a'):
    tmp_link_m.append(link_m.get('href'))

tmp_link_new_m = []
for val in tmp_link_m:
    if val != None:
        tmp_link_new_m.append(val)
        

sub_m = 'techniques/T'
res_m = [i for i in tmp_link_new_m if sub_m in i]
new_res_m = list(set(res_m))

for j in new_res_m:
    technique_m.append(list(filter(None, j.split('/'))))
    
for e in technique_m:
    technique_id_m.append(e[1])
    
new_technique_id_m = list(set(technique_id_m))

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