# !/usr/bin/env python3
# -*- coding: utf-8 -*-
from Common.Base import MyConverter
from Common.Sm import MySmRemote, MySm



def gm_base_enc_test():
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
    message_cipher = gmr.remote_external_enc_sm4_cbc(message4.encode(), key4, iv4)
    print(f"CBC外部Key 加密后数据为 [{message_cipher}]")
    message_plain = gmr.remote_external_dec_sm4_cbc(message_cipher, key4, iv4)
    print(f"CBC外部Key 解密后数据为 [{message_plain}]")

    # 调用本地gmssl lib进行sm4 cbd加解密
    message_cipher_local = MySm.sm4_cbc_enc(message4, key4, iv4)
    print(f"GMSSL CBC加密相同数据后的加密值为 [{message_cipher_local}]")
    message_plain_local = MySm.sm4_cbc_dec(message_cipher_local, key4, iv4)
    print(f"GMSSL CBC解密后数据为 [{message_plain_local}]")

if __name__ == "__main__":
    # gm_base_enc_test()
    message = "Hello World"
    # key = MySm.random_bytes32()
    # print(key.hex())
    fix_key = "10f9f482d075ea0438dd56e739444930920bcc16742016fb8f84dfab3f7f84c6"
    print(MySm.sm3_hmac_digest_with_key_hex(message, MyConverter.hex_to_base64(fix_key)))

    print(MySm.sm3_digest_bytes("Hello World").hex())



