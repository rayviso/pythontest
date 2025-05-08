# !/usr/bin/env python3
# -*- coding: utf-8 -*-

from Common.Base import MyCiphers, MyConverter, MyTimer, MyMath
from Common.Sm import MySmRemote, MySm
from Common.DB import MyMssql
from Common.Random import MyRandom

import threading
import multiprocessing
import os
import signal
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import ThreadPoolExecutor

my_key = "9a129abc0c8f6a31c520e97c66a49701"
my_key_32 = "9a129abc0c8f6a31c520e97c66a49701d20a24ce5f8510d64c2303de066945fa"
my_iv = "d20a24ce5f8510d64c2303de066945fa"
b_key = MyConverter.hex_string_to_bytes(my_key)
b_key_32 = MyConverter.hex_string_to_bytes(my_key_32)
b_iv = MyConverter.hex_string_to_bytes(my_iv)
b_nonce = MySm.random_bytes(12)


# sm4算法测试函数：分别调用了远程加解密接口和GMSSL本地加解密接口
def gm_base_sm4_test():
    print(f"GM SM4 算法测试数据：")

    gmr = MySmRemote()

    # 调用远程restful api进行sm4 ecb加解密（内部key）
    message1 = "Hello World"
    print(f"ECB内部Key 加密原始数据为 [{message1}]")
    message_cipher = gmr.remote_internal_enc_sm4_ecb(message1)
    print(f"ECB内部Key 加密后数据为 [{message_cipher}]")
    message_plain = gmr.remote_internal_dec_sm4_ecb(message_cipher)
    print(f"ECB内部Key 解密后数据为 [{message_plain}]")

    # 调用远程restful api进行sm4 cbc加解密（内部key）
    message2 = "Hello World"
    iv2 = MySm.random_bytes16()
    print(f"CBC内部Key 加密原始数据为 [{message2}], 加密初始向量iv为 [{iv2.hex()}]")
    cipher_text = gmr.remote_internal_enc_sm4_cbc(message2, iv2)
    print(f"CBC内部Key 加密后数据为 [{cipher_text}]")
    plain_text = gmr.remote_internal_dec_sm4_cbc(cipher_text, iv2)
    print(f"CBC内部Key 解密后数据为 [{plain_text}]")

    # 调用远程restful api进行sm4 ecb加解密
    message3 = "Hello World"
    key3 = MySm.random_bytes16()
    print(f"ECB外部Key 加密原始数据为 [{message3}], 加密Key为 [{key3.hex()}]")
    message_cipher = gmr.remote_external_enc_sm4_ecb(message3, key3)
    print(f"ECB外部Key 加密后数据为 [{message_cipher}]")
    message_plain = gmr.remote_external_dec_sm4_ecb(message_cipher, key3)
    print(f"ECB外部Key 解密后数据为 [{message_plain}]")

    # 调用远程restful api进行sm4 cbc加解密
    message4 = "Hello World"
    key4 = MySm.random_bytes16()
    iv4 = MySm.random_bytes16()
    print(f"CBC外部Key 加密原始数据为 [{message4}], 加密Key为 [{key4.hex()}], 加密初始向量iv为 [{iv4.hex()}]")
    message_cipher = gmr.remote_external_enc_sm4_cbc(message4, key4, iv4)
    print(f"CBC外部Key 加密后数据为 [{message_cipher}]")
    message_plain = gmr.remote_external_dec_sm4_cbc(message_cipher, key4, iv4)
    print(f"CBC外部Key 解密后数据为 [{message_plain}]")

    # 调用本地gmssl lib进行sm4 cbd加解密
    message_cipher_local = MySm.sm4_cbc_enc(message4, key4, iv4)
    print(f"GMSSL CBC加密相同数据后的加密值为 [{message_cipher_local}]")
    message_plain_local = MySm.sm4_cbc_dec(message_cipher_local, key4, iv4)
    print(f"GMSSL CBC解密后数据为 [{message_plain_local}]")


# sm3算法测试，抓哟
def gm_base_sm3_test():
    print(f"GM SM3 算法测试数据：")
    message = "Hello World"
    key16_base64 = "YAsTIIQYbze9jiedI9cTHQ=="
    key16_hex = "600b132084186f37bd8e279d23d7131d"
    # print(f"原始数据为 [{message}]，SM3_HMAC算法KEY为 [{key16_base64}]，SM3_HMAC值为 [{MySm.sm3_hmac_digest_with_key_base64(message, MyConverter.base64_to_bytes(key16_base64))}]")
    print(
        f"原始数据为 [{message}]，SM3_HMAC算法KEY为 [{key16_hex}]，SM3_HMAC值为 [{MySm.sm3_hmac_digest_with_key_hex(message, MyConverter.hex_string_to_bytes(key16_hex))}]")
    print(f"原始数据为 [{message}]，SM3值为 [{MySm.sm3_digest_hex(message)}]")
    print(f"原始数据为 [{message}]，MD5值为 [{MyConverter.md5_string(message)}]")


# 用来实现mssql测试数据库的初始化工作：主要是完成在users表中插入数据，没执行一次，插入模拟用户数据?行
@MyTimer.timer_decorator
def mssql_db_init(table_name: str):
    password = MySm.sm4_cbc_dec("7K/RSidOyNf7jXQeomexdA==", MyConverter.hex_string_to_bytes(my_key),
                                MyConverter.hex_string_to_bytes(my_iv))
    mssql = MyMssql("192.168.0.198", "MyDB", "sa", password)
    insert_query = f"""INSERT INTO {table_name} (id, name, gender, id_card_number, phone_number, address, ukey_id, password, passwordhash)
    	VALUES (NEWID(), ?, ?, ?, ?, ?, ?, ?, ?);"""

    # 随机写入所需要数据
    for n in range(2):
        params = []
        params.clear()
        for i in range(1000):
            params.append(MyRandom.random_person_info())
        mssql.execute_insert_many_fast(insert_query, params)

    mssql.close_connection()


# 用来测试将users表中的md5值通过sm4算法进行加密
@MyTimer.timer_decorator
def enc_md5_to_sm4_local(table_name: str, b_key=None, b_iv=None):
    print(f"当前调用本地GMSSL进行md5值SM4加密操作")
    password = MySm.sm4_cbc_dec("7K/RSidOyNf7jXQeomexdA==", MyConverter.hex_string_to_bytes(my_key),
                                MyConverter.hex_string_to_bytes(my_iv))
    mssql = MyMssql("192.168.0.198", "MyDB", "sa", password)
    select_count_query = f"""SELECT count(*) FROM {table_name};"""
    table_rows = mssql.execute_select_count(select_count_query)
    print(f"当前表为{table_name}, 当前表有{table_rows}行数据")
    rst = MyMath.take_the_whole_and_the_remainder(table_rows, 10000)
    pages = rst[0]
    # last_page_rows = rst[1]

    select_count_query = f"""select * from {table_name} order by indexnumber offset ? rows fetch next ? rows only;"""
    sm4_values = []
    update_query = f"""update {table_name} set passwordhashsm4 = ? where id = ?;"""
    for i in range(pages):
        sm4_values.clear()
        rows = mssql.execute_select_by_pages_general(select_count_query, i + 1, 10000)
        # 调用本地gmssl lib库来实现sm4加密
        sm4_values = local_sm4_enc_time_cost(rows, b_key, b_iv)
        mssql.execute_update_many_fast(update_query, sm4_values)

    mssql.close_connection()


@MyTimer.timer_decorator
def enc_md5_to_aes_local(table_name: str, b_key=None, b_iv=None):
    print(f"当前调用本地Openssl进行md5值AES加密操作")
    password = MySm.sm4_cbc_dec("7K/RSidOyNf7jXQeomexdA==", MyConverter.hex_string_to_bytes(my_key),
                                MyConverter.hex_string_to_bytes(my_iv))
    mssql = MyMssql("192.168.0.198", "MyDB", "sa", password)
    select_count_query = f"""SELECT count(*) FROM {table_name};"""
    table_rows = mssql.execute_select_count(select_count_query)
    print(f"当前表为{table_name}, 当前表有{table_rows}行数据")
    rst = MyMath.take_the_whole_and_the_remainder(table_rows, 10000)
    pages = rst[0]
    # last_page_rows = rst[1]

    select_count_query = f"""select * from {table_name} order by indexnumber offset ? rows fetch next ? rows only;"""
    aes_values = []
    update_query = f"""update {table_name} set passwordhashaes = ? where id = ?;"""
    for i in range(pages):
        aes_values.clear()
        rows = mssql.execute_select_by_pages_general(select_count_query, i + 1, 10000)
        # 调用本地gmssl lib库来实现sm4加密
        aes_values = local_aes_enc_time_cost(rows, b_key, b_iv)
        mssql.execute_update_many_fast(update_query, aes_values)
    mssql.close_connection()


# @MyTimer.timer_decorator
def local_sm4_enc_time_cost(rows: list, b_key, b_iv):
    sm4_values = []
    for row in rows:
        # print(row[9], row[8], MySm.sm4_cbc_enc(row[8], b_key, b_iv))
        sm4_values.append((MySm.sm4_cbc_enc(row[8], b_key, b_iv), row[0]))  # list中存的数据是tuple
    return sm4_values


def local_aes_enc_time_cost(rows: list, b_key, b_iv):
    aes_values = []
    for row in rows:
        # print(row[9], row[8], MySm.sm4_cbc_enc(row[8], b_key, b_iv))
        # aes_values.append((MyConverter.bytes_to_base64(MyCiphers.aes_cbc_enc(row[8].encode(), b_key, b_iv)), row[0]))  # list中存的数据是tuple
        aes_values.append((MyConverter.bytes_to_base64(MyCiphers.aes_gcm_enc(row[8].encode(), b_key, b_iv)),
                           row[0]))  # list中存的数据是tuple
    return aes_values


@MyTimer.timer_decorator
def enc_md5_to_sm4_remote(table_name: str, b_key=None, b_iv=None):
    # 调用远程密码资源池来实现sm4加密
    print(f"当前调用Restful API进行md5值SM4加密操作")
    password = MySm.sm4_cbc_dec("7K/RSidOyNf7jXQeomexdA==", MyConverter.hex_string_to_bytes(my_key),
                                MyConverter.hex_string_to_bytes(my_iv))
    mssql = MyMssql("192.168.0.198", "MyDB", "sa", password)
    mssql_connection_string = mssql.connect_string

    select_count_query = f"""SELECT count(*) FROM {table_name};"""
    table_rows = mssql.execute_select_count(select_count_query)
    print(f"当前表为{table_name}, 当前表有{table_rows}行数据")
    rst = MyMath.take_the_whole_and_the_remainder(table_rows, 10000)
    pages = rst[0]
    # last_page_rows = rst[1]

    select_count_query = f"""select indexnumber, passwordhash from {table_name} order by indexnumber offset ? rows fetch next ? rows only;"""
    sm4_values = []
    update_query = f"""update {table_name} set passwordhashsm4remote = ? where id = ?;"""
    for i in range(pages):
        sm4_values.clear()
        rows = mssql.execute_select_by_pages_general(select_count_query, i + 1, 10000)
        # 调用本地gmssl lib库来实现sm4加密
        remote_sm4_enc_time_cost(rows, b_key, b_iv, mssql_connection_string)

    mssql.close_connection()


# def signal_handler():
#     print("收到终止信号，结束所有进程")
#     for p in processes:
#         p.terminate()
#     exit(0)

# 采用多进程进行对数据的处理
@MyTimer.timer_decorator
def remote_sm4_enc_time_cost(rows: list, b_key, b_iv, mssql_connection_string: str):
    # signal.signal(signal.SIGINT, signal_handler)

    rows_list = MyConverter.chunk_by_number(rows, 12)

    # for each_splited_rows in splited_rows:
    #     print(len(each_splited_rows))

    mssql = MyMssql(connect_string=mssql_connection_string)

    processes = []
    for rows in rows_list:
        # 多进程处理
        process = multiprocessing.Process(target=multi_threads_to_remote_sm, args=(rows, b_key, b_iv, mssql))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()

    # 进程池处理
    # with ProcessPoolExecutor(max_workers=12) as executor:
    #     for each_splited_rows in splited_rows:
    #         executor.submit(multi_threads_to_remote_sm, each_splited_rows, b_key, b_iv)


# 每个进程采用多线程进行处理
def multi_threads_to_remote_sm(rows: list, b_key, b_iv, mssql: MyMssql):
    smr = MySmRemote()
    # print(f"进程ID:{os.getpid()} 所处理数据从第{rows[0][0]}行开始")

    # 每个进程起100个线程，每个线程处理一组数据
    rows_list = MyConverter.chunk_by_number(rows, 100)

    threads = []

    for rows in rows_list:
        thread = threading.Thread(target=remote_sm4, args=(rows, b_key, b_iv, smr, mssql))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # with ThreadPoolExecutor(max_workers=100) as thread_pool_executor:
    #     results = []
    #     for row in rows:
    #         results = [thread_pool_executor.submit(smr.remote_external_enc_sm4_cbc, row[8], b_key, b_iv)]
    #         thread_pool_executor.shutdown(wait=True)
    #
    #     for r in results:
    #         print(r)


# 多线程调用的加密函数
def remote_sm4(rows: list, b_key, b_iv, smr: MySmRemote, mssql: MyMssql):
    # print(f"线程ID为：{threading.get_ident()}, 当前线程处理行数从{rows[0][9]}行开始")
    sm4_values = []
    for row in rows:
        sm4_values.append((row[0], smr.remote_external_enc_sm4_cbc(row[1], b_key, b_iv)))
        print(sm4_values[1])





@MyTimer.timer_decorator
def sm4_cbc_enc_test(data: list):
    sm4_enc_ciphertext = []
    for d in data:
        sm4_enc_ciphertext.append(MySm.sm4_cbc_enc(d[0], b_key, b_iv))
    # print(len(sm4_enc_ciphertext))
    # print(f"加密后样本数据 【{sm4_enc_ciphertext[0]}】")


@MyTimer.timer_decorator
def aes_cbc_enc_128_test(data: list):
    ase_enc_ciphertext = []
    for d in data:
        ase_enc_ciphertext.append(MyConverter.bytes_to_base64(MyCiphers.aes_cbc_enc(d[0].encode(), b_key, b_iv)))
    # print(len(ase_enc_ciphertext))
    # print(f"加密后样本数据 【{ase_enc_ciphertext[0]}】")


@MyTimer.timer_decorator
def aes_gcm_enc_128_test(data: list):
    ase_enc_ciphertext = []
    for d in data:
        ase_enc_ciphertext.append(MyConverter.bytes_to_base64(MyCiphers.aes_gcm_enc(d[0].encode(), b_key, b_nonce)))
    # print(len(ase_enc_ciphertext))
    # print(f"加密后样本数据 【{ase_enc_ciphertext[0]}】")


@MyTimer.timer_decorator
def aes_cbc_enc_256_test(data: list):
    ase_enc_ciphertext = []
    for d in data:
        ase_enc_ciphertext.append(MyConverter.bytes_to_base64(MyCiphers.aes_cbc_enc(d[0].encode(), b_key_32, b_iv)))
    # print(len(ase_enc_ciphertext))
    # print(f"加密后样本数据 【{ase_enc_ciphertext[0]}】")


@MyTimer.timer_decorator
def aes_gcm_enc_256_test(data: list):
    ase_enc_ciphertext = []
    for d in data:
        ase_enc_ciphertext.append(MyConverter.bytes_to_base64(MyCiphers.aes_gcm_enc(d[0].encode(), b_key_32, b_nonce)))
    # print(len(ase_enc_ciphertext))
    # print(f"加密后样本数据 【{ase_enc_ciphertext[0]}】")


# 用来进行算法性能对比
# sm4_cbc && aes_cbc && aes_gcm
def ciphers_vs():
    print(f"进行算法性能对比")
    rst = get_sample_data()
    sm4_cbc_enc_test(rst)
    aes_cbc_enc_256_test(rst)
    aes_cbc_enc_128_test(rst)
    aes_gcm_enc_128_test(rst)
    aes_gcm_enc_256_test(rst)


# 从数据库中获取10000条数据用来进行测试
def get_sample_data():
    password = MySm.sm4_cbc_dec("7K/RSidOyNf7jXQeomexdA==", MyConverter.hex_string_to_bytes(my_key),
                                MyConverter.hex_string_to_bytes(my_iv))
    mssql = MyMssql("192.168.0.198", "MyDB", "sa", password)
    select_query = "select top 10000 passwordhash from users;"
    rst = mssql.execute_select(select_query)
    mssql.close_connection()
    return rst


if __name__ == "__main__":
    gm_base_sm4_test() # sm4算法测试
    # gm_base_sm3_test() # sm3算法测试
    # mssql_db_init("users") # 初始化数据库，向users表中插入数据
    # 一组性能对比函数 sm4_cbc 和 aes_gcm
    # enc_md5_to_aes_local("users", b_key, b_iv)  # 本地openssl加密：将密码的md5值进行aes加密算法，并把值update到mssql中
    # enc_md5_to_sm4_local("users", b_key, b_iv)  # 本地gmssl加密：将密码的md5值进行sm4加密算法，并把值update到mssql中
    # ciphers_vs() # 横向对比对称加密算法
    # 远程api加密：将md5值进行sm4加密算法
    # enc_md5_to_sm4_remote("users", b_key, b_iv)
