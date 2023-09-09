import hashlib
import os
import csv
import requests
import time
import socket
import socks
from stem import Signal
from stem.control import Controller
##使用tor才可以成功


# url = 'https://www.virustotal.com/api/v3/files'
url = 'https://www.virustotal.com/api/v3/files/{hash}'
headers1 = {'x-apikey': ''}
headers2 = {'x-apikey': ''}
headers3 = {'x-apikey': ''}
headers4 = {'x-apikey': ''}
headers5 = {'x-apikey': ''}
proxies = {
                'http': 'socks5://127.0.0.1:9050',
                'https': 'socks5://127.0.0.1:9050'
            }
num = 0
header_list = [headers1,headers2,headers3,headers4,headers5]

folder_path = 'F:/binary'

def switch_proxy():
    """
    切换 Tor 代理地址
    :return: NULL
    """
    with Controller.from_port() as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)

with open('threat_categories_binary.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['File Name', 'hash_value', 'Suggested_threat_label', 'Popular_threat_category', 'Popular_threat_name'])

    for file_name in os.listdir(folder_path):
        headers = header_list[num]    ##判断用哪个api
        print("现在是api", headers)
        file_path = folder_path + '/' + file_name
        with open(file_path, "rb") as f:
            b = f.read()
            hash_value = hashlib.sha256(b).hexdigest()
            print("hash值:",hash_value)
        try:
            succeed = 1 ##如果成功了，就变0
            while(succeed):
                time.sleep(30)
                response = requests.get(url.format(hash=hash_value), headers=headers,proxies = proxies)
                a = requests.get("http://checkip.amazonaws.com",proxies = proxies).text
                print("ip:" + a)
                if response.status_code == 200:
                    succeed = 0
                    data = response.json()
                    suggested_threat_label = None
                    popular_threat_category = None
                    popular_threat_name = None
                    try:
                        if data['data']:
                            try:
                                if data['data']['attributes']:
                                    try:
                                        if data['data']['attributes']['popular_threat_classification']:
                                            try:
                                                if data['data']['attributes']['popular_threat_classification'][
                                                    'suggested_threat_label']:
                                                    suggested_threat_label = \
                                                        data['data']['attributes']['popular_threat_classification'][
                                                            'suggested_threat_label']
                                            except KeyError:
                                                suggested_threat_label = None
                                            try:
                                                if data['data']['attributes']['popular_threat_classification'][
                                                    'popular_threat_category']:
                                                    popular_threat_category = \
                                                        data['data']['attributes']['popular_threat_classification'][
                                                            'popular_threat_category']
                                            except KeyError:
                                                popular_threat_category = None
                                            try:
                                                if data['data']['attributes']['popular_threat_classification'][
                                                    'popular_threat_name']:
                                                    popular_threat_name = \
                                                        data['data']['attributes']['popular_threat_classification'][
                                                            'popular_threat_name']
                                            except KeyError:
                                                popular_threat_name = None
                                    except KeyError:
                                        suggested_threat_label = None
                                        popular_threat_category = None
                                        popular_threat_name = None
                            except KeyError:
                                suggested_threat_label = None
                                popular_threat_category = None
                                popular_threat_name = None
                    except KeyError:
                        suggested_threat_label = None
                        popular_threat_category = None
                        popular_threat_name = None

                    writer.writerow(
                        [file_name, hash_value,suggested_threat_label, popular_threat_category,popular_threat_name])
                    print(file_name, hash_value,suggested_threat_label, popular_threat_category,popular_threat_name)
                else:
                    print('Error:', response.status_code)
                    # writer.writerow([file_name, hash_value, None, None, None])
                    flag = 1 ##如果ip变化了，就变成0 ，停止循环
                    while flag:
                        switch_proxy()
                        b = requests.get("http://checkip.amazonaws.com",proxies = proxies).text
                        if b == a:
                            continue
                        else:
                            print("新的ip是：", b)
                            flag = 0

        except requests.exceptions.ConnectionError:
            if num+1 == len(header_list):
                print("顺利跑完了！")
                exit()
            else:
                num = num + 1
                headers =header_list[num]
                print("现在是api",headers)
                succeed = 1  ##如果成功了，就变0
                while (succeed):
                    time.sleep(30)
                    response = requests.get(url.format(hash=hash_value), headers=headers,proxies = proxies)
                    a = requests.get("http://checkip.amazonaws.com", proxies = proxies).text
                    print("ip:" + a)
                    if response.status_code == 200:
                        succeed = 0
                        data = response.json()
                        suggested_threat_label = None
                        popular_threat_category = None
                        popular_threat_name = None
                        try:
                            if data['data']:
                                try:
                                    if data['data']['attributes']:
                                        try:
                                            if data['data']['attributes']['popular_threat_classification']:
                                                try:
                                                    if data['data']['attributes']['popular_threat_classification'][
                                                        'suggested_threat_label']:
                                                        suggested_threat_label = \
                                                            data['data']['attributes'][
                                                                'popular_threat_classification'][
                                                                'suggested_threat_label']
                                                except KeyError:
                                                    suggested_threat_label = None
                                                try:
                                                    if data['data']['attributes']['popular_threat_classification'][
                                                        'popular_threat_category']:
                                                        popular_threat_category = \
                                                            data['data']['attributes'][
                                                                'popular_threat_classification'][
                                                                'popular_threat_category']
                                                except KeyError:
                                                    popular_threat_category = None
                                                try:
                                                    if data['data']['attributes']['popular_threat_classification'][
                                                        'popular_threat_name']:
                                                        popular_threat_name = \
                                                            data['data']['attributes'][
                                                                'popular_threat_classification'][
                                                                'popular_threat_name']
                                                except KeyError:
                                                    popular_threat_name = None
                                        except KeyError:
                                            suggested_threat_label = None
                                            popular_threat_category = None
                                            popular_threat_name = None
                                except KeyError:
                                    suggested_threat_label = None
                                    popular_threat_category = None
                                    popular_threat_name = None
                        except KeyError:
                            suggested_threat_label = None
                            popular_threat_category = None
                            popular_threat_name = None

                        writer.writerow(
                            [file_name, hash_value,suggested_threat_label, popular_threat_category,
                             popular_threat_name])
                        print(file_name, hash_value,suggested_threat_label, popular_threat_category,popular_threat_name)
                    else:
                        # print('Error:', response.status_code)
                        # writer.writerow([file_name, hash_value, None, None, None])
                        flag = 1  ##如果ip变化了，就变成0 ，停止循环
                        while flag:
                            switch_proxy()
                            b = requests.get("http://checkip.amazonaws.com",proxies= proxies).text
                            if b == a:
                                continue
                            else:
                                print("新的ip是：", b)
                                flag = 0
