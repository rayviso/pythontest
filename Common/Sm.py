from Common.Base import *
from gmssl import *
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ, namedtype

import requests
import json
import base64

from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 禁用特定警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# 或者禁用所有 urllib3 警告
# requests.packages.urllib3.disable_warnings()


class MySM2PublicKeyIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "algorithm",  # ANSI X9.62 public key type (ecPublicKey)
            univ.ObjectIdentifier()
        ),
        namedtype.NamedType(
            "curve",  # SM2 ECC identifier
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


class MySm(object):

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
    def sm2_private_key_decrypt(private_key: Sm2Key, ciphertext) -> bytes:
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

        sm2key_pair = MySM2KeyPair(bytes(sm2key.public_key).hex(), bytes(sm2key.private_key).hex(),
                                   base64.b64encode(bytes(sm2key.public_key)).decode(),
                                   base64.b64encode(bytes(sm2key.private_key)).decode(), MySm.sm2_public_key_get_04(
                MySm.sm2_public_key_base64_full(base64.b64encode(bytes(sm2key.public_key)).decode())))
        return sm2key_pair

    # TODO SM3
    @staticmethod
    def sm3_digest_bytes(data: str):
        sm3 = Sm3()
        sm3.update(data.encode())
        return sm3.digest()

    @staticmethod
    def sm3_digest_hex(string):
        sm3 = Sm3()
        sm3.update(string.encode("utf-8"))
        return sm3.digest().hex()

    @staticmethod
    def sm3_digest_base64(data: str) -> str:
        sm3 = Sm3()
        sm3.update(data.encode("utf-8"))
        return base64.b64encode(sm3.digest()).decode("utf-8")

    @staticmethod
    def sm3_hmac_digest_hex(data: str) -> str:
        key = rand_bytes(SM3_HMAC_MIN_KEY_SIZE)
        sm3_hmac = Sm3Hmac(key)
        sm3_hmac.update(data.encode("utf-8"))
        return sm3_hmac.generate_mac().hex()

    @staticmethod
    def sm3_hmac_digest_base64(data: str):
        key = rand_bytes(SM3_HMAC_MIN_KEY_SIZE)
        sm3_hmac = Sm3Hmac(key)
        sm3_hmac.update(data.encode("utf-8"))
        return base64.b64encode(sm3_hmac.generate_mac()).decode("utf-8")

    @staticmethod
    def sm3_hmac_digest_with_key_hex(data: str, key: bytes) -> str:
        sm3_hmac = Sm3Hmac(key)
        sm3_hmac.update(data.encode("utf-8"))
        return sm3_hmac.generate_mac().hex()

    @staticmethod
    def sm3_hmac_digest_with_key_base64(data: str, key: bytes) -> str:
        sm3_hmac = Sm3Hmac(key)
        sm3_hmac.update(data.encode("utf-8"))
        return base64.b64encode(sm3_hmac.generate_mac()).decode("utf-8")

    # TODO SM4
    @staticmethod
    def sm4_cbc_enc(data: str, b_key: bytes, b_iv: bytes) -> str:
        sm4_cbc = Sm4Cbc(b_key, b_iv, DO_ENCRYPT)
        cipher_text = sm4_cbc.update(data.encode())
        cipher_text += sm4_cbc.finish()
        return MyConverter.bytes_to_base64(cipher_text)

    @staticmethod
    def sm4_cbc_dec(data: str, b_key: bytes, b_iv: bytes) -> str:
        sm4_dec = Sm4Cbc(b_key, b_iv, DO_DECRYPT)
        plain_text = sm4_dec.update(MyConverter.base64_to_bytes(data))
        plain_text += sm4_dec.finish()
        return MyConverter.bytes_to_string_utf8(plain_text)

    # TODO Random
    @staticmethod
    def random_bytes(n: int):
        return rand_bytes(n)

    @staticmethod
    def random_bytes16():
        return rand_bytes(16)

    @staticmethod
    def random_bytes32():
        return rand_bytes(32)


class MySmRemote(object):

    def __init__(self):
        self.enc_token = ""
        self.sign_token = ""

        self.base_url = "https://101.91.108.14:8867"

        self.enc_app_code = "encrypt"
        self.enc_tenant_code = "zqyl"
        self.sign_app_code = "sign"
        self.sign_tenant_code = "zqyl"
        self.enc_internal_key_name = "sk_encrypt_sm4"

        self.enc_user_info = {
            "username": "zqyl@encrypt",
            "password": "1234Jjm!@"
        }

        self.sign_user_info = {
            "username": "zqyl@sign",
            "password": "1234Jjm!@"
        }

        self.token_url = "/ccsp/auth/app/v1/token"
        self.token_full_url = self.base_url + self.token_url

        self.sm4_enc_internal_url = "/pki/api/v6/encrypt/internal/symmetric"
        self.sm4_enc_internal_full_url = self.base_url + self.sm4_enc_internal_url

        self.sm4_dec_internal_url = "/pki/api/v6/decrypt/internal/symmetric"
        self.sm4_dec_internal_full_url = self.base_url + self.sm4_dec_internal_url

        self.sm4_enc_external_url = "/pki/api/v6/encrypt/external/symmetric"
        self.sm4_enc_external_full_url = self.base_url + self.sm4_enc_external_url

        self.sm4_dec_external_url = "/pki/api/v6/decrypt/external/symmetric"
        self.sm4_dec_external_full_url = self.base_url + self.sm4_dec_external_url

    def token(self, request_json_data: dict) -> str:

        request_headers = {
            "Content-Type": "application/json",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "Accept-Encoding": "gzip, deflate, br"
        }

        try:
            response = requests.post(self.token_full_url, headers=request_headers, json=request_json_data, verify=False)
            if response.status_code == 200:
                json_data = json.loads(json.dumps(response.json()))
                status = str(json_data["status"])
                if status == "0":
                    token = str(json_data["data"]["accessToken"])
                    return token
                else:
                    message = str(json_data["message"])
                    return message
            else:
                return str(response.status_code)
        except requests.RequestException as e:
            return str(e)

    def get_2_tokens(self, enc_user_info: dict, sign_user_info: dict):
        self.enc_token = self.token(enc_user_info)
        self.sign_token = self.token(sign_user_info)

    def remote_internal_enc_sm4_ecb(self, data: str) -> str:

        if self.enc_token == "":
            self.get_2_tokens(self.enc_user_info, self.sign_user_info)

        request_headers = {
            "Content-Type": "application/json",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "Accept-Encoding": "gzip, deflate, br",
            "X-SW-Authorization-Token": self.enc_token,
            "X-SW-Authorization-TenantCode": self.enc_tenant_code,
            "X-SW-Authorization-AppCode": self.enc_app_code
        }

        request_json_data = {
            "keyName": self.enc_internal_key_name,
            "algType": "SGD_SM4_ECB",
            "iv": "",
            "inData": MyConverter.string_to_base64(data),
            "paddingType": "PKCS7PADDING"
        }

        try:
            response = requests.post(self.sm4_enc_internal_full_url, headers=request_headers, json=request_json_data,
                                     verify=False)
            if response.status_code == 200:
                json_data = json.loads(json.dumps(response.json()))
                status = str(json_data["status"])
                code = str(json_data["code"])
                if status == "200":
                    outData = str(json_data["result"]["outData"])
                    return outData
                elif status == "500" and code == "00000002":
                    self.get_2_tokens(self.enc_user_info, self.sign_user_info)
                    return self.remote_internal_enc_sm4_ecb(data)
                else:
                    message = str(json_data["message"])
                    return message
            else:
                return str(response.status_code)
        except requests.RequestException as e:
            return str(e)

    def remote_internal_enc_sm4_cbc(self, data: str, b_iv: bytes) -> str:
        if self.enc_token == "":
            self.get_2_tokens(self.enc_user_info, self.sign_user_info)

        request_headers = {
            "Content-Type": "application/json",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "Accept-Encoding": "gzip, deflate, br",
            "X-SW-Authorization-Token": self.enc_token,
            "X-SW-Authorization-TenantCode": self.enc_tenant_code,
            "X-SW-Authorization-AppCode": self.enc_app_code
        }

        request_json_data = {
            "keyName": self.enc_internal_key_name,
            "algType": "SGD_SM4_CBC",
            "iv": MyConverter.bytes_to_base64(b_iv),
            "inData": MyConverter.string_to_base64(data),
            "paddingType": "PKCS7PADDING"
        }

        try:
            response = requests.post(self.sm4_enc_internal_full_url, headers=request_headers, json=request_json_data,
                                     verify=False)
            if response.status_code == 200:
                json_data = json.loads(json.dumps(response.json()))
                status = str(json_data["status"])
                code = str(json_data["code"])
                if status == "200" and code == "0":
                    out_data = str(json_data["result"]["outData"])
                    return out_data
                elif status == "500" and code == "00000002":
                    self.get_2_tokens(self.enc_user_info, self.sign_user_info)
                    return self.remote_internal_enc_sm4_cbc(data, b_iv)
                else:
                    message = str(json_data["message"])
                    return message
            else:
                return str(response.status_code)
        except requests.RequestException as e:
            return str(e)

    def remote_internal_dec_sm4_ecb(self, data: str) -> str:
        if self.enc_token == "":
            self.get_2_tokens(self.enc_user_info, self.sign_user_info)

        request_headers = {
            "Content-Type": "application/json",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "Accept-Encoding": "gzip, deflate, br",
            "X-SW-Authorization-Token": self.enc_token,
            "X-SW-Authorization-TenantCode": self.enc_tenant_code,
            "X-SW-Authorization-AppCode": self.enc_app_code
        }

        request_json_data = {
            "keyName": self.enc_internal_key_name,
            "algType": "SGD_SM4_ECB",
            "inData": data,
            "paddingType": "PKCS7PADDING"
        }

        try:
            response = requests.post(self.sm4_dec_internal_full_url, headers=request_headers, json=request_json_data,
                                     verify=False)
            if response.status_code == 200:
                json_data = json.loads(json.dumps(response.json()))
                status = str(json_data["status"])
                code = str(json_data["code"])
                if status == "200":
                    outData = str(json_data["result"]["outData"])
                    return MyConverter.base64_to_string(outData)
                elif status == "500" and code == "00000002":
                    self.get_2_tokens(self.enc_user_info, self.sign_user_info)
                    return self.remote_internal_enc_sm4_ecb(data)
                else:
                    message = str(json_data["message"])
                    return message
            else:
                return str(response.status_code)
        except requests.RequestException as e:
            return str(e)

    def remote_internal_dec_sm4_cbc(self, data: str, b_iv: bytes) -> str:
        if self.enc_token == "":
            self.get_2_tokens(self.enc_user_info, self.sign_user_info)

        request_headers = {
            "Content-Type": "application/json",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "Accept-Encoding": "gzip, deflate, br",
            "X-SW-Authorization-Token": self.enc_token,
            "X-SW-Authorization-TenantCode": self.enc_tenant_code,
            "X-SW-Authorization-AppCode": self.enc_app_code
        }

        request_json_data = {
            "keyName": self.enc_internal_key_name,
            "algType": "SGD_SM4_CBC",
            "iv": MyConverter.bytes_to_base64(b_iv),
            "inData": data,
            "paddingType": "PKCS7PADDING"
        }

        try:
            response = requests.post(self.sm4_dec_internal_full_url, headers=request_headers, json=request_json_data,
                                     verify=False)
            if response.status_code == 200:
                json_data = json.loads(json.dumps(response.json()))
                status = str(json_data["status"])
                code = str(json_data["code"])
                if status == "200" and code == "0":
                    out_data = str(json_data["result"]["outData"])
                    b_iv = str(json_data["result"]["iv"])
                    return MyConverter.base64_to_string(out_data)
                elif status == "500" and code == "00000002":
                    self.get_2_tokens(self.enc_user_info, self.sign_user_info)
                    return self.remote_internal_dec_sm4_cbc(data, b_iv)
                else:
                    message = str(json_data["message"])
                    return message
            else:
                return str(response.status_code)
        except requests.RequestException as e:
            return str(e)

    def remote_external_enc_sm4_ecb(self, data: str, b_key: bytes) -> str:
        if self.enc_token == "":
            self.get_2_tokens(self.enc_user_info, self.sign_user_info)

        request_headers = {
            "Content-Type": "application/json",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "Accept-Encoding": "gzip, deflate, br",
            "X-SW-Authorization-Token": self.enc_token,
            "X-SW-Authorization-TenantCode": self.enc_tenant_code,
            "X-SW-Authorization-AppCode": self.enc_app_code
        }

        request_json_data = {
            "keyValue": MyConverter.bytes_to_base64(b_key),
            "algType": "SGD_SM4_ECB",
            "isEnc": "false",
            "inData": MyConverter.string_to_base64(data),
            "paddingType": "PKCS7PADDING"
        }

        try:
            response = requests.post(self.sm4_enc_external_full_url, headers=request_headers, json=request_json_data,
                                     verify=False)
            if response.status_code == 200:
                json_data = json.loads(json.dumps(response.json()))
                status = str(json_data["status"])
                code = str(json_data["code"])
                if status == "200":
                    outData = str(json_data["result"]["outData"])
                    return outData
                elif status == "500" and code == "00000002":
                    self.get_2_tokens(self.enc_user_info, self.sign_user_info)
                    return self.remote_internal_enc_sm4_ecb(data)
                else:
                    message = str(json_data["message"])
                    return message
            else:
                return str(response.status_code)
        except requests.RequestException as e:
            return str(e)

    def remote_external_enc_sm4_cbc(self, b_data: bytes, b_key: bytes, b_iv: bytes) -> str:
        if self.enc_token == "":
            self.get_2_tokens(self.enc_user_info, self.sign_user_info)

        request_headers = {
            "Content-Type": "application/json",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "Accept-Encoding": "gzip, deflate, br",
            "X-SW-Authorization-Token": self.enc_token,
            "X-SW-Authorization-TenantCode": self.enc_tenant_code,
            "X-SW-Authorization-AppCode": self.enc_app_code
        }

        request_json_data = {
            "keyValue": MyConverter.bytes_to_base64(b_key),
            "algType": "SGD_SM4_CBC",
            "isEnc": "false",
            "inData": MyConverter.bytes_to_base64(b_data),
            "iv": MyConverter.bytes_to_base64(b_iv),
            "paddingType": "PKCS7PADDING"
        }

        try:
            response = requests.post(self.sm4_enc_external_full_url, headers=request_headers, json=request_json_data,
                                     verify=False)
            if response.status_code == 200:
                json_data = json.loads(json.dumps(response.json()))
                status = str(json_data["status"])
                code = str(json_data["code"])
                if status == "200":
                    outData = str(json_data["result"]["outData"])
                    return outData
                elif status == "500" and code == "00000002":
                    self.get_2_tokens(self.enc_user_info, self.sign_user_info)
                    return self.remote_internal_enc_sm4_ecb(data)
                else:
                    message = str(json_data["message"])
                    return message
            else:
                return str(response.status_code)
        except requests.RequestException as e:
            return str(e)

    def remote_external_dec_sm4_ecb(self, data: str, b_key: str) -> str:
        if self.enc_token == "":
            self.get_2_tokens(self.enc_user_info, self.sign_user_info)

        request_headers = {
            "Content-Type": "application/json",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "Accept-Encoding": "gzip, deflate, br",
            "X-SW-Authorization-Token": self.enc_token,
            "X-SW-Authorization-TenantCode": self.enc_tenant_code,
            "X-SW-Authorization-AppCode": self.enc_app_code
        }

        request_json_data = {
            "keyValue": MyConverter.bytes_to_base64(b_key),
            "algType": "SGD_SM4_ECB",
            "isEnc": "false",
            "inData": data,
            "paddingType": "PKCS7PADDING"
        }

        try:
            response = requests.post(self.sm4_dec_external_full_url, headers=request_headers, json=request_json_data,
                                     verify=False)
            if response.status_code == 200:
                json_data = json.loads(json.dumps(response.json()))
                status = str(json_data["status"])
                code = str(json_data["code"])
                if status == "200":
                    outData = str(json_data["result"]["outData"])
                    return MyConverter.base64_to_string(outData)
                elif status == "500" and code == "00000002":
                    self.get_2_tokens(self.enc_user_info, self.sign_user_info)
                    return self.remote_internal_enc_sm4_ecb(data)
                else:
                    message = str(json_data["message"])
                    return message
            else:
                return str(response.status_code)
        except requests.RequestException as e:
            return str(e)

    def remote_external_dec_sm4_cbc(self, data: str, b_key: bytes, b_iv: bytes) -> str:
        if self.enc_token == "":
            self.get_2_tokens(self.enc_user_info, self.sign_user_info)

        request_headers = {
            "Content-Type": "application/json",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "Accept-Encoding": "gzip, deflate, br",
            "X-SW-Authorization-Token": self.enc_token,
            "X-SW-Authorization-TenantCode": self.enc_tenant_code,
            "X-SW-Authorization-AppCode": self.enc_app_code
        }

        request_json_data = {
            "keyValue": MyConverter.bytes_to_base64(b_key),
            "algType": "SGD_SM4_CBC",
            "isEnc": "false",
            "inData": data,
            "iv": MyConverter.bytes_to_base64(b_iv),
            "paddingType": "PKCS7PADDING"
        }

        try:
            response = requests.post(self.sm4_dec_external_full_url, headers=request_headers, json=request_json_data,
                                     verify=False)
            if response.status_code == 200:
                json_data = json.loads(json.dumps(response.json()))
                status = str(json_data["status"])
                code = str(json_data["code"])
                if status == "200":
                    outData = str(json_data["result"]["outData"])
                    return MyConverter.base64_to_string(outData)
                elif status == "500" and code == "00000002":
                    self.get_2_tokens(self.enc_user_info, self.sign_user_info)
                    return self.remote_internal_enc_sm4_ecb(data)
                else:
                    message = str(json_data["message"])
                    return message
            else:
                return str(response.status_code)
        except requests.RequestException as e:
            return str(e)
