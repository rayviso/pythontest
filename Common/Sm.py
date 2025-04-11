from Common.Base import *
from gmssl import *
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ, namedtype

import base64

class MySM2PublicKeyIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "algorithm",  # ANSI X9.62 public key type (ecPublicKey)
            univ.ObjectIdentifier()
        ),
        namedtype.NamedType(
            "curve",      # SM2 ECC identifier
            univ.ObjectIdentifier()
        )
    )

# 定义外层的完整结构
class MySM2PublicKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "publicKeyIdentifier",
            MySM2PublicKeyIdentifier()  # 嵌套内部的 SEQUENCE
        ),
        namedtype.NamedType(
            "publicKey",
            univ.BitString()  # BIT STRING 类型
        )
    )

class MySM2KeyPair:
    sm2key_pair = [
        ("public_key_hex", str),
        ("private_key_hex", str),
        ("public_key_base64", str),
        ("private_key_base64", str),
        ("public_key_04", str)
    ]

    def __init__(self, public_key_hex, private_key_hex, public_key_base64, private_key_base64, public_key_04):
        self.public_key_hex = public_key_hex
        self.private_key_hex = private_key_hex
        self.public_key_base64 = public_key_base64
        self.private_key_base64 = private_key_base64
        self.public_key_04 = public_key_04


class MySm():

    def __init__(self):
        pass

    # TODO SM2
    @staticmethod
    def sm2_private_key_sign(private_key: Sm2Key, dgst: bytes):
        return private_key.sign(dgst)

    @staticmethod
    def sm2_public_key_verify(public_key: Sm2Key, dgst, sig):
        return public_key.verify(dgst, sig)

    @staticmethod
    def sm2_public_key_encrypt(public_key: Sm2Key, plaintext: str) -> bytes:
        return public_key.encrypt(plaintext)

    @staticmethod
    def sm2_private_key_decrypt(private_key: Sm2Key, ciphertext)-> bytes:
        return private_key.decrypt(ciphertext)

    @staticmethod
    def sm2_import_private_key_from_encrypted_pem(private_key_file_path, password) -> Sm2Key:
        private_key = Sm2Key()
        private_key.import_encrypted_private_key_info_pem(private_key_file_path, password)
        return private_key

    @staticmethod
    def sm2_import_public_key_from_pem(public_key_file_path) -> Sm2Key:
        public_key = Sm2Key()
        public_key.import_public_key_info_pem(public_key_file_path)
        return public_key

    @staticmethod
    def sm2_export_key_to_pem_file(private_key_file_path, password, public_key_file_path):
        sm2key = Sm2Key()
        sm2key.generate_key()
        # 输出私钥PEM格式文件
        sm2key.export_encrypted_private_key_info_pem(private_key_file_path, password)
        private_key = Sm2Key()
        private_key.import_encrypted_private_key_info_pem(private_key_file_path, password)
        # 输出公钥PEM格式文件
        sm2key.export_public_key_info_pem(public_key_file_path)
        public_key = Sm2Key()
        public_key.import_public_key_info_pem(public_key_file_path)
        # print(base64.b64encode(bytes(private_key.private_key)).decode())

    @staticmethod
    def sm2_get_public_key_from_private_key_():
        sm2publickey = MySM2PublicKey()
        pass

    @staticmethod
    def sm2_public_key_get_04(public_key_base64):
        # 自定义SM2 PublicKey类，并使用相关参数进行解析
        decoded_data, _ = decoder.decode(base64.b64decode(public_key_base64), asn1Spec=MySM2PublicKey())
        bit_string = decoded_data["publicKey"]

        # 不定义ASN1类，按照下标进行内容解析
        # decoded_data, _ = decoder.decode(base64.b64decode(public_key_base64))
        # bit_string = decoded_data[1]
        return MyConverter.bit_to_hex(str(bit_string))

    @staticmethod
    def sm2_public_key_get_04_base64(public_key_base64):
        # 自定义SM2 PublicKey类，并使用相关参数进行解析
        decoded_data, _ = decoder.decode(base64.b64decode(public_key_base64), asn1Spec=MySM2PublicKey())
        bit_string = decoded_data["publicKey"]

        # 不定义ASN1类，按照下标进行内容解析
        # decoded_data, _ = decoder.decode(base64.b64decode(public_key_base64))
        # bit_string = decoded_data[1]
        return MyConverter.hex_to_string(MyConverter.bit_to_hex(str(bit_string)))

    # 添加头尾标记，并每 64 字符换行
    # 最终文件是asn1格式文件
    @staticmethod
    def sm2_public_key_base64_to_pem(base64_key: str) -> str:
        pem = "-----BEGIN PUBLIC KEY-----\n"
        base64_key = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE" + base64_key
        # 按每 64 字符分割字符串
        chunks = [base64_key[i:i + 64] for i in range(0, len(base64_key), 64)]
        pem += "\n".join(chunks) + "\n"
        pem += "-----END PUBLIC KEY-----"
        return pem

    @staticmethod
    def sm2_public_key_base64_full(base64_key: str) -> str:
        return "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE" + base64_key

    @staticmethod
    def sm2_get_public_key_base64(key: Sm2Key):
        return base64.b64encode(bytes(key.public_key)).decode()

    @staticmethod
    def sm2_get_private_key_base64(key: Sm2Key):
        return base64.b64encode(bytes(key.private_key)).decode()

    @staticmethod
    def sm2_key_pair():
        sm2key = Sm2Key()
        sm2key.generate_key()

        sm2key_pair = MySM2KeyPair(bytes(sm2key.public_key).hex(), bytes(sm2key.private_key).hex(), base64.b64encode(bytes(sm2key.public_key)).decode(), base64.b64encode(bytes(sm2key.private_key)).decode(), MySm.sm2_public_key_get_04(MySm.sm2_public_key_base64_full(base64.b64encode(bytes(sm2key.public_key)).decode())))
        return sm2key_pair

    # TODO SM3
    @staticmethod
    def sm3_digest():
        sm3 = Sm3()
        return sm3.digest()

    @staticmethod
    def sm3_digest_hex(string):
        sm3 = Sm3()
        sm3.update(string.encode("utf-8"))
        return sm3.digest().hex()

    @staticmethod
    def sm3_digest_base64(string):
        sm3 = Sm3()
        sm3.update(string.encode("utf-8"))
        return base64.b64encode(sm3.digest()).decode("utf-8")

    @staticmethod
    def sm3_hmac_digest_hex(string):
        key = rand_bytes(SM3_HMAC_MIN_KEY_SIZE)
        sm3_hmac = Sm3Hmac(key)
        sm3_hmac.update(string.encode("utf-8"))
        return sm3_hmac.generate_mac().hex()

    @staticmethod
    def sm3_hmac_digest_base64(string):
        key = rand_bytes(SM3_HMAC_MIN_KEY_SIZE)
        sm3_hmac = Sm3Hmac(key)
        sm3_hmac.update(string.encode("utf-8"))
        return base64.b64encode(sm3_hmac.generate_mac()).decode("utf-8")

    @staticmethod
    def sm3_hmac_digest_with_key_hex(string, key):
        sm3_hmac = Sm3Hmac(key)
        sm3_hmac.update(string.encode("utf-8"))
        return sm3_hmac.generate_mac().hex()

    @staticmethod
    def sm3_hmac_digest_with_key_base64(string, key):
        sm3_hmac = Sm3Hmac(key)
        sm3_hmac.update(string.encode("utf-8"))
        return base64.b64encode(sm3_hmac.generate_mac()).decode("utf-8")

    @staticmethod
    def random_bytes16():
        return rand_bytes(16)

    @staticmethod
    def random_bytes32():
        return rand_bytes(32)

