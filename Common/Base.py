from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# from pyasn1_modules import
# from pyasn1.codec.der import decoder, encoder

import base64
import hashlib
import time
import os


class MyTimer(object):
    def __init__(self, interval, callback):
        self.interval = interval
        self.callback = callback

    @staticmethod
    def timer_decorator(func):
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            result = func(*args, **kwargs)
            end = time.perf_counter()
            print(f"{func.__name__} 执行耗时: {end - start:.4f} 秒")
            return result

        return wrapper


# TODO：完成ASN1类型数据解析的基础类
class MyASN1(object):
    def __init__(self):
        pass

    # @staticmethod
    # def


class MyConverter(object):

    def __init__(self):
        pass

    # string -> bytes @utf-8
    @staticmethod
    def string_to_bytes_utf8(string):
        return string.encode("utf-8")

    # string -> bytes @ascii
    @staticmethod
    def string_to_bytes_ascii(string):
        return string.encode("ascii")

    # string -> bytes @gbk
    @staticmethod
    def string_to_bytes_gbk(string):
        return string.encode("gbk")

    # string -> base64
    @staticmethod
    def string_to_base64(string):
        return base64.b64encode(string.encode()).decode()

    # string -> hex
    @staticmethod
    def string_to_hex(string):
        return string.encode().hex()

    # string -> hex
    @staticmethod
    def string_to_hex_with_space(string):
        return ' '.join(f"{b:02x}" for b in string.encode())

    # bytes -> string
    @staticmethod
    def bytes_to_string_windows1252(bytes):
        return bytes.decode("windows-1252")

    # bytes -> string
    @staticmethod
    def bytes_to_string_latin1(bytes):
        return bytes.decode("latin-1")

    # bytes -> string
    @staticmethod
    def bytes_to_string_utf8(bytes):
        return bytes.decode("utf8")

    # bytes -> string
    @staticmethod
    def bytes_to_string_gbk(bytes):
        return bytes.decode("gbk")

    # bytes -> string
    @staticmethod
    def bytes_to_string_ascii(bytes):
        return bytes.decode("ascii")

    # bytes -> base64
    @staticmethod
    def bytes_to_base64(bytes):
        return base64.b64encode(bytes).decode()

    # bytes -> hex
    @staticmethod
    def bytes_to_hex(bytes):
        return bytes.hex()

    # bytes -> hex
    @staticmethod
    def bytes_to_hex_with_space(bytes):
        return ' '.join(f"{b:02x}" for b in bytes)

    # base64 -> hex
    @staticmethod
    def base64_to_hex(b64):
        try:
            return base64.b64decode(b64).hex()
        except ValueError:
            raise ValueError("Invalid Value")

    # base64 -> bytes
    @staticmethod
    def base64_to_bytes(b64):
        try:
            return base64.b64decode(b64)
        except ValueError:
            raise ValueError("Invalid Value")

    # base64 -> string
    @staticmethod
    def base64_to_string(b64):
        try:
            return base64.b64decode(b64).decode("utf-8")
        except ValueError:
            raise ValueError("Invalid Value")

    # hex -> base64
    @staticmethod
    def hex_to_base64(hex):
        try:
            return base64.b64encode(bytes.fromhex(hex))
        except ValueError:
            raise ValueError("Invalid Value")

    # hex -> bytes
    @staticmethod
    def hex_string_to_bytes(hex):
        try:
            return bytes.fromhex(hex)
        except ValueError:
            raise ValueError("Invalid Value")

    # hex -> string
    @staticmethod
    def hex_to_string(hex):
        try:
            return base64.b64encode(bytes.fromhex(hex)).decode("utf-8")
        except ValueError:
            raise ValueError("Invalid Value")

    # bit -> hex 2进制转16进制
    @staticmethod
    def bit_to_hex(bit_str):
        padding = (4 - len(bit_str) % 4) % 4
        bit_str_padded = '0' * padding + bit_str
        # 转换为hex字符串
        hex_str = ''.join([format(int(bit_str_padded[i:i + 4], 2), 'x') for i in range(0, len(bit_str_padded), 4)])
        return hex_str

    @staticmethod
    def md5_string(data: str) -> str:
        # 必须将字符串编码为字节（常用 UTF-8）
        byte_data = data.encode('utf-8')
        # 创建 MD5 对象并更新数据
        md5 = hashlib.md5()
        md5.update(byte_data)
        # 返回十六进制哈希值
        return md5.hexdigest()

    @staticmethod
    def chunk_by_size(mylist: list, chunk_size: int):
        return [mylist[i:i + chunk_size] for i in range(0, len(mylist), chunk_size)]

    @staticmethod
    def chunk_by_number(mylist: list, n: int):
        k, m = divmod(len(mylist), n)
        return [mylist[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n)]

    @staticmethod
    def chunk_by_condition(mylist: list, condition_func):
        # 按照不同条件分
        # 默认奇偶数分
        groups = {}
        for item in mylist:
            key = condition_func(item)
            if key not in groups:
                groups[key] = []
            groups[key].append(item)
        return list(groups.values())


class MyCiphers(object):
    def __init__(self):
        pass

    # TODO: HASH 哈希算法
    @staticmethod
    def hash_md5_string(data: str) -> str:
        # 必须将字符串编码为字节（常用 UTF-8）
        byte_data = data.encode('utf-8')
        # 创建 MD5 对象并更新数据
        md5 = hashlib.md5()
        md5.update(byte_data)
        # 返回十六进制哈希值
        return md5.hexdigest()

    @staticmethod
    def hash_md5_bytes(data: bytes) -> str:
        md5 = hashlib.md5()
        md5.update(bytes)
        return md5.hexdigest()

    @staticmethod
    def hash_sha1(data: bytes) -> str:
        """计算 SHA-1 哈希值"""
        sha1 = hashlib.sha1()
        sha1.update(data)
        return sha1.hexdigest()  # 返回十六进制字符串

    @staticmethod
    def hash_sha256(data: bytes) -> str:
        """计算 SHA-256 哈希值"""
        sha256 = hashlib.sha256()
        sha256.update(data)
        return sha256.hexdigest()

    # 密钥长度必须为 16(AES-128), 24(AES-192) 或 32(AES-256) 字节
    # 初始向量必须为 16位 可以将IV和密文一起存储
    @staticmethod
    def aes_cbc_enc(plaintext, key, iv):
        # 创建 AES-CBC 加密器
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        # 处理填充
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        # 加密数据
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext

    @staticmethod
    def aes_cbc_dec(ciphertext, key, iv):
        # 创建 AES-CBC 解密器
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )

        # 解密数据
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # 去除填充
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext

    @staticmethod
    def aes_gcm_enc(plaintext, key, nonce):
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return ciphertext

    @staticmethod
    def aes_gcm_dec(ciphertext, key, nonce):
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)


class MyMath(object):
    def __init__(self):
        pass

    @staticmethod
    def take_the_whole_and_the_remainder(total: int, divisor: int) -> tuple[int, int]:
        return total // divisor + 1, total % divisor
