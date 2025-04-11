#!/usr/bin/python3
# coding=utf-8

# from Lib.PyLib3 import Base
# from Lib.Excel import Excel

import sys
import requests
import json
import random
import socket
import struct
import time
import elasticsearch
import elasticsearch
from elasticsearch.connection import RequestsHttpConnection


src_random_ip_pool = ['192.168.10.222/0']
dst_random_ip_pool = ['172.16.200.10/23']

dst_random_port_pool = ['80', '443', '8080', '22', '3389', '445', '135', '1521', '3306', '1433']
protocol_pool = ['tcp', 'udp']

def get_random_ip(RANDOM_IP_POOL):
    str_ip = RANDOM_IP_POOL[random.randint(0,len(RANDOM_IP_POOL) - 1)]
    str_ip_addr = str_ip.split('/')[0]
    str_ip_mask = str_ip.split('/')[1]
    ip_addr = struct.unpack('>I',socket.inet_aton(str_ip_addr))[0]
    mask = 0x0
    for i in range(31, 31 - int(str_ip_mask), -1):
        mask = mask | ( 1 << i)
    ip_addr_min = ip_addr & (mask & 0xffffffff)
    ip_addr_max = ip_addr | (~mask & 0xffffffff)
    return socket.inet_ntoa(struct.pack('>I', random.randint(ip_addr_min, ip_addr_max)))

def create_post_json():
    print(random.randint(0,100))
    pass


def http_get_npm_flowinfo():
    npm_url = "http://172.16.200.153"
    pass


# 获取es状态
def http_get_elk_info():

    # url的通用配置
    url_headers = {
        "Content-Type": "application/json"
    }

    url_auth = {"auth": ("elk", "ning1234")}

    #
    url_es = "http://172.16.203.181:9200/"
    resp_elk_info = requests.get(url_es, headers = url_headers, **url_auth)

    if resp_elk_info.status_code == 200:
        print(json.loads(resp_elk_info.content.decode("utf-8")))
    else:
        print(resp_elk_info.status_code)

    # 获取集群状态
    url_es_cluster_health = "http://172.16.203.181:9200/_cluster/health?pretty"
    resp_es_cluster_health = requests.get(url_es_cluster_health, headers=url_headers, **url_auth)

    if resp_es_cluster_health.status_code == 200:
        print(json.loads(resp_es_cluster_health.content.decode("utf-8")))
    else:
        print(resp_es_cluster_health.status_code)

    # 获取集群状态
    url_es_health = "http://172.16.203.182:9200/_cat/health?pretty"
    resp_es_health = requests.get(url_es_health, headers=url_headers, **url_auth)

    if resp_es_health.status_code == 200:
        print(resp_es_health.content.decode("utf-8"))
    else:
        print(resp_es_health.status_code)

# 生成给flow索引提交的jsons
def get_url_data_flow_jsons(i):
    flow_jsons = ''
    for n in range(i):
        flow_json = '{ "index": { } }\r\n{"srcip": "%s", "srcport": "%s", "dstip": "%s", "dstport": "%s", "protocol": "%s"}\r\n' % (
        get_random_ip(src_random_ip_pool), str(random.randint(10001, 65535)), get_random_ip(dst_random_ip_pool),
        dst_random_port_pool[random.randint(0, len(dst_random_port_pool) - 1)], protocol_pool[random.randint(0, 1)])
        flow_jsons = flow_jsons + flow_json
    return flow_jsons


# es数据提交主函数，提交到flow索引下
def post_flow_data():
    # url_path = "http://172.16.203.182:9200/flow/_bulk"
    url_path = "http://172.16.203.181:9200/flow/_bulk"
    url_data = get_url_data_flow_jsons(3000)
    url_auth = {"auth": ("elastic", "ning1234")}
    url_headers = {
        "Content-Type": "application/json"
    }

    resp = requests.post(url_path, url_data, headers=url_headers, **url_auth)

    # json_data = '{"src_ip": "229.190.117.207", "src_port": "53838", "dst_ip": "172.16.200.235", "dst_port": "443", "protocol": "tcp"}'
    # resp = requests.post(url2, json_data, headers = url_headers, **elk_auth)
    # print(resp.status_code)
    # print(resp.content.decode("utf-8"))

    if resp.status_code == 200:
        print("Post done")
    else:
        print(resp.status_code)
        print(resp.content.decode("utf-8"))


# 从es中进行数据查询
def get_flow_data():
    url_path = "http://172.16.203.182:9200/flow/_search"
    url_data =  {
        "query": {
            "match_all": {
            }
        },
        "sort": [
            {
                "@timestamp": "desc"
            }
        ]
    }
    url_data = json.dumps(url_data)
    url_headers = {
        "Content-Type": "application/json"
    }
    url_auth = {"auth": ("elk", "ning1234")}

    resp = requests.post(url_path, url_data, headers= url_headers, **url_auth)

    if resp.status_code == 200:
        print("Search done")
        print(resp.content.decode("utf-8"))
    else:
        print(resp.status_code)
        print(resp.content.decode("utf-8"))

# 用来对es进行数据提交和数据查询，并在post数据之后进行查询，确定post数据是否提交进入到es中
def demo_for_es():
    while True:
        t1 = time.perf_counter()
        post_flow_data()
        print(f'coast:{time.perf_counter() - t1:.8f}s')
        # t2 = time.perf_counter()
        # get_flow_data()
        # print(f'coast:{time.perf_counter() - t2:.8f}s')
        # time.sleep(1)


def search_es():
    # url的通用配置
    url_headers = {
        "Content-Type": "application/json"
    }

    url_auth = {"auth": ("elk", "ning1234")}

    url_path = "http://172.16.203.181:9200/flow/_search"

    url_data = {
      "query": {

          "range":{
              "@timestamp":{
                    "gte": "2021-06-29T13:00:00",
                    "lt": "2021-06-29T13:00:01"
              }
          }
      },
      "_source": "false",
      "sort": [
        {
          "@timestamp": "desc"
        }
      ]
    }

    url_data = json.dumps(url_data)

    resp_search = requests.post(url_path, url_data, headers=url_headers, **url_auth)
    if resp_search.status_code == 200:
        print(resp_search.content.decode("utf-8"))
        pass
    else:
        print(resp_search.status_code)
        print(resp_search.content.decode("utf-8"))
    pass


# elasticsearch类的使用测试
def es_test():

    # https://elasticsearch-py.readthedocs.io/en/v7.13.2/
    # 相关使用参考
    es = elasticsearch.Elasticsearch(["172.16.203.181:9200", "172.16.203.182:9200", "172.16.203.183:9200"],
                                     http_auth=("elk", "ning1234"),
                                     # scheme="https",
                                     # port=443,
                                     # sniff_on_start=True,
                                     # sniffer_timeout=None,
                                     # sniff_on_connection_fail=True,
                                     # sniffer_timeout=60,
                                     connect_class=RequestsHttpConnection,
    )

    if es.cluster.health(wait_for_status="yellow"):
        pass

    pass


def es_search_test():

    # 使用post和body进行传参

    url_auth={"auth":("elk","ning1234")}
    url_headers={"Content-Type":"application/json"}

    # url_path="http://172.16.203.182:9200/flow/_search?pretty"
    # url_data={
    #     "query":{
    #         "term":{
    #             "dst_port":"22"
    #         }
    #     },
    #     "from":"0",
    #     "size":"100"
    # }

    url_path="http://172.16.203.182:9200/flow/_search"
    url_data={
        "from": "0",
        "size": "100",
        "query":{
            "terms":{
                "dst_port":["22","3389"]
            },
        },
        "sort": [{"dst_port":"asc"}, {"dst_ip":{"order":"desc"}}],
        "search_after":["22","172.16.200.133"]
    }

    resp = requests.post(url_path, json.dumps(url_data), headers=url_headers,**url_auth)

    if resp.status_code == 200:
        # print(type(resp.content.decode("utf-8")))
        print(type(json.loads(resp.content.decode("utf-8"))))
        d=json.loads(resp.content.decode("utf-8"))["hits"]["hits"]
        i=1
        for ditem in d:
            print(("row:%s\t"+ditem["_source"]["src_ip"]+" to "+ditem["_source"]["dst_ip"])%(i))
            i=i+1
    else:
        print(resp.status_code)




    # if resp.status_code == 200:
    #     # print(type(resp.content.decode("utf-8")))
    #     id=json.loads(resp.content.decode("utf-8"))["_scroll_id"]
    #
    #     url_path="http://172.16.203.182:9200/_search/scroll"
    #     url_data={
    #         "scroll":"5m",
    #         "scroll_id":id
    #     }
    #
    #     resp=requests.post(url_path, json.dumps(url_data), headers=url_headers, **url_auth)
    #     if resp.status_code == 200:
    #         d=json.loads(resp.content.decode("utf-8"))
    #         # print(d)
    #
    # else:
    #     print(resp.status_code)



    # 使用get和url进行传参

    # url_get_path = "http://172.16.203.182:9200/flow/_search?pretty&q=dst_port:22&from=0&size=100"
    #
    # resp_get = requests.get(url_get_path, headers=url_headers, **url_auth)
    # if resp_get.status_code==200:
    #     d=json.loads(resp_get.content.decode("utf-8"))["hits"]["hits"]
    #
    #     i = 1
    #     for ditem in d:
    #         print(("row:%s\t" + ditem["_source"]["src_ip"] + " to " + ditem["_source"]["dst_ip"]) % (i))
    #         i = i + 1
    #
    # else:
    #     print(resp_get.status_code)

    pass

def main():
    t1 = time.perf_counter()
    # es_search_test()
    demo_for_es()
    # http_get_elk_info()
    # es_test()
    # search_es()
    print(f'coast:{time.perf_counter() - t1:.8f}s')

# 主函数
if __name__ == "__main__":
    main()



