#!/usr/bin/python3
# coding=utf-8

import maxminddb

def main():
    # reader = maxminddb.open_database('D:\\GeoLite2\\mmdb\\GeoLite2-City.mmdb')
    reader = maxminddb.open_database('D:\\GeoLite2\\mmdb\\GeoLite2-City.mmdb')
    print(reader.get("114.114.114.114"))
    # print(reader.metadata())
    # print(reader.get_with_prefix_len("8.8.8.8"))
    reader.close()
    pass

if __name__ == "__main__":
    main()

