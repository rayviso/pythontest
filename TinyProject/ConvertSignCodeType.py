# !/usr/bin/env python3
# -*- coding: utf-8 -*-
# v2 -- fix 0

import sys
import base64
# from cgi import print_form

from pyasn1.codec.der.decoder import decode
from pyasn1.type import univ, namedtype

# GLOBAL_SIGNCODE = 'MUMyM0M0RDY3RjdGMjg3RjJCQUNGNjYyQTI1MDdGMEFDQjQwQTMyNEIwQkFEM0MxMjdDRDE0RUM1MEZENDc4NDkyNURCMDJEMkY5RDQ1QjI5M0RFNjRFRkE3NDA0NjY5QzBEMzI3RjIyQkIxNzk0RTA4MkYzNEZEOEQ0QTEwRUY='
# GLOBAL_SIGNCODE = "MEUCIQD8OX1ZhkIwArf3ZvajC9UD+nxpkDwk0ROkl2PQDoxVRAIgLYVxOvUU7NuAI/ZB2lh1ICV/NGmyFYCZRNV/a4ZiDBY="
# GLOBAL_SIGNCODE = "MEYCIQC+gRscHJer9cBHgn2Q7BmXriwz+f5o/l5MuYNn3uSMYgIhAO1gRmZrqmuAANeMpH3HGV6LREQI42qq5/DqtC8Wkay+"
GLOBAL_SIGNCODE = "MEUCIA2w0RRes0LH0/r47nEt3vFhvw4HpWAZeWhsY9BEi6xUAiEA5lPB77z27puixPFSbHJRDmZIePvE4gVxPJuAMciTjGc="

# < SEQUENCE >
# < INTEGER > 0x0DB0D1145EB342C7D3FAF8EE712DDEF161BF0E07A5601979686C63D0448BAC54 < / INTEGER >
# < INTEGER > 0x00E653C1EFBCF6EE9BA2C4F1526C72510E664878FBC4E205713C9B8031C8938C67 < / INTEGER >
# < / SEQUENCE >

class MyASN1Structure(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('s', univ.Integer()),
        namedtype.NamedType('r', univ.Integer())
    )

def main():
    print(f'hello world')
    print(f'[Test] hello python --- Convert Sign Code Type --')
    print(f'[原始签名值，Base64编码]： {GLOBAL_SIGNCODE}')
    signature_data_asn1_der = base64.b64decode(GLOBAL_SIGNCODE)
    print(f'[原始签名值，解Base64编码，16进制格式]：{signature_data_asn1_der}')
    decoded_data, _ = decode(signature_data_asn1_der, asn1Spec=MyASN1Structure())

    hex_s = hex(decoded_data['s'])[2:]
    hex_r = hex(decoded_data['r'])[2:]

    # 补0操作
    len_s = len(hex_s)
    if(len_s == 64):
        pass
    else:
        n = 64 - len_s
        patch_0_1 = ['0'] * n
        hex_s = ''.join(patch_0_1) + hex_s

    len_r = len(hex_r)
    if(len_r == 64):
        pass
    else:
        n = 64 - len_r
        patch_0_2 = ['0'] * n
        hex_r = ''.join(patch_0_2) + hex_r

    print(f"[ASN1进行解析，第一部分，s，16进制格式]:", hex_s)
    print(f"[ASN1进行解析，第一部分，r，16进制格式]:", hex_r)

    zero_list = ['0'] * 64
    s_mix = zero_list + list(hex_s) + zero_list + list(hex_r)
    s_mix_str = ''.join(s_mix)

    print(f"[进行32个0字节补位操作，分别在s和r前边补位，实际是64个0，16进制格式]:", s_mix_str)
    hex_s_mix_str = bytes.fromhex(s_mix_str)
    # print(hex_s_mix_str)
    print(f"[再对补位完成的进行进行Base64编码，得到最终含A的签名数据]:", base64.b64encode(hex_s_mix_str).decode())

if __name__ == "__main__":
    sys.exit(main())