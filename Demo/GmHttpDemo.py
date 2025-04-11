# !/usr/bin/env python3
# -*- coding: utf-8 -*-

from Common.Base import MyConverter
import requests
import json

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class SmRemote(object):

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
        # print(global_enc_token)
        # print(global_sign_token)

    def sm4_ecb_enc_internal_remote(self, data: str) -> str:

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
            response = requests.post(self.sm4_enc_internal_full_url, headers=request_headers, json=request_json_data, verify=False)
            if response.status_code == 200:
                json_data = json.loads(json.dumps(response.json()))
                status = str(json_data["status"])
                code = str(json_data["code"])
                if status == "200":
                    outData = str(json_data["result"]["outData"])
                    return outData
                elif status == "500" and code == "00000002":
                    self.get_2_tokens(self.enc_user_info, self.sign_user_info)
                    return self.sm4_ecb_enc_internal_remote(data)
                else:
                    message = str(json_data["message"])
                    return message
            else:
                return str(response.status_code)
        except requests.RequestException as e:
            return str(e)

    def sm4_ecb_dec_internal_remote(self, data: str) -> str:
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
            response = requests.post(self.sm4_dec_internal_full_url, headers=request_headers, json=request_json_data, verify=False)
            if response.status_code == 200:
                json_data = json.loads(json.dumps(response.json()))
                status = str(json_data["status"])
                code = str(json_data["code"])
                if status == "200":
                    outData = str(json_data["result"]["outData"])
                    return MyConverter.base64_to_string(outData)
                elif status == "500" and code == "00000002":
                    self.get_2_tokens(self.enc_user_info, self.sign_user_info)
                    return self.sm4_ecb_enc_internal_remote(data)
                else:
                    message = str(json_data["message"])
                    return message
            else:
                return str(response.status_code)
        except requests.RequestException as e:
            return str(e)

    def sm4_cbc_enc_internal_remote(self, data: str, iv: str) -> str:

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
            "iv": MyConverter.string_to_base64(iv),
            "inData": MyConverter.string_to_base64(data),
            "paddingType": "PKCS7PADDING"
        }

        try:
            response = requests.post(self.sm4_enc_internal_full_url, headers=request_headers, json=request_json_data, verify=False)
            if response.status_code == 200:
                json_data = json.loads(json.dumps(response.json()))
                status = str(json_data["status"])
                code = str(json_data["code"])
                if status == "200":
                    outData = str(json_data["result"]["outData"])
                    return outData
                elif status == "500" and code == "00000002":
                    self.get_2_tokens(self.enc_user_info, self.sign_user_info)
                    return self.sm4_ecb_enc_internal_remote(data)
                else:
                    message = str(json_data["message"])
                    return message
            else:
                return str(response.status_code)
        except requests.RequestException as e:
            return str(e)


    def sm4_cbd_dec_internal_remote(self, data: str, iv: str) -> str:
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
            "iv": iv,
            "inData": data,
            "paddingType": "PKCS7PADDING"
        }

        try:
            response = requests.post(self.sm4_dec_internal_full_url, headers=request_headers, json=request_json_data, verify=False)
            if response.status_code == 200:
                json_data = json.loads(json.dumps(response.json()))
                status = str(json_data["status"])
                code = str(json_data["code"])
                if status == "200":
                    outData = str(json_data["result"]["outData"])
                    return MyConverter.base64_to_string(outData)
                elif status == "500" and code == "00000002":
                    self.get_2_tokens(self.enc_user_info, self.sign_user_info)
                    return self.sm4_ecb_enc_internal_remote(data)
                else:
                    message = str(json_data["message"])
                    return message
            else:
                return str(response.status_code)
        except requests.RequestException as e:
            return str(e)

if __name__ == "__main__":
    sr = SmRemote()
    cipher_text = sr.sm4_ecb_enc_internal_remote("hello world")
    print(cipher_text)
    plain_text = sr.sm4_ecb_dec_internal_remote(cipher_text)
    print(plain_text)
    cipher_text = sr.sm4_cbc_enc_internal_remote("hello world", "0011223344556677")
    print(cipher_text)


