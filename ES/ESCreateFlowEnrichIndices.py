#!/usr/bin/python3
# coding=utf-8

import csv


def create_index_ethertype():
    pass

def create_index_ipprotocol():
    with open('..\\Data\\ipprotocol.csv', 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        # print(type(reader))
        indexcmdheader = 'POST _bulk\r'
        indexcmdall = indexcmdheader
        for row in reader:
            # print(row)
            indexcmd = '{ "index": { "_index": "ipprotocol" }}\r'
            indexcmd = indexcmd + '{ "number": "%s", "oxcode" : "%s", "name" : "%s", "description" : "%s"}\r' % (row[0], row[1], row[2], row[3])
            indexcmdall = indexcmdall + indexcmd
        with open('..\\Data\\ipprotocol.post', 'w', encoding='utf-8') as f2:
            f2.write(indexcmdall)
            print("file ipprotocol.post is created")
    pass

def create_index_service():
    pass

def main():
    create_index_ethertype()
    create_index_ipprotocol()
    create_index_service()
    pass

if __name__ == '__main__':
    main()