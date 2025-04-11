from gmssl import Sm2Key

from Base import MyConverter
from Sm import MySm

import base64

def sm_test():
    # pair = MySm.sm2_key_pair()
    # print("------------------------------------------------------------------------------------------------------------------------------------")
    # print("SM2 Public Key is :", pair.public_key_base64)
    # print()
    # print(MySm.sm2_public_key_base64_to_pem(pair.public_key_base64))
    # print()
    # print("SM2 Public Key 04 :", pair.public_key_04.upper())
    # print("------------------------------------------------------------------------------------------------------------------------------------")
    # print("SM2 Private Key is :", pair.private_key_base64)
    #
    # print("------------------------------------------------------------------------------------------------------------------------------------")

    # 生成sm2 公私钥对
    # MySm.sm2_export_key_to_pem_file("../Data/rootcakey.pem", "123456", "../Data/rootcapub.pem")

    public_key = MySm.sm2_import_public_key_from_pem("../Data/rootcapub.pem")
    public_key_base64 = MySm.sm2_get_public_key_base64(public_key)
    print("read public key is :", public_key_base64)
    publick_key_04_base64 = MySm.sm2_public_key_get_04_base64(MySm.sm2_public_key_base64_full(public_key_base64))
    print("read public 04 key is :", publick_key_04_base64)
    publick_key_04 = MySm.sm2_public_key_get_04(MySm.sm2_public_key_base64_full(public_key_base64))
    print("read public 04 key is :", publick_key_04)
    private_key = MySm.sm2_import_private_key_from_encrypted_pem("../Data/rootcakey.pem", "123456")
    print("read private key is :", MySm.sm2_get_private_key_base64(private_key))
    print("------------------------------------------------------------------------------------------------------------------------------------")

    ciphertext = MySm.sm2_public_key_encrypt(public_key,"wangning")
    print("sm2 public encrypt data is :", MyConverter.bytes_to_base64(ciphertext))
    decrypted = MySm.sm2_private_key_decrypt(private_key, ciphertext)
    print(decrypted.decode())
    print("------------------------------------------------------------------------------------------------------------------------------------")
    dgst = MySm.sm3_digest()
    print(dgst)
    print("sm3 hash value is :", MyConverter.bytes_to_base64(dgst))
    print(dgst)
    sig = MySm.sm2_private_key_sign(private_key, dgst)
    print("sm3 sign value is :", MyConverter.bytes_to_base64(sig))
    print("sm2 verify result :", MySm.sm2_public_key_verify(public_key, dgst, sig))

def main():
    sm_test()

if __name__ == '__main__':
    main()
