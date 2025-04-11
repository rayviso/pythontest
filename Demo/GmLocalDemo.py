from gmssl import *
from Base import MyConverter
import base64

def sm4CBC():
    # key = rand_bytes(SM4_KEY_SIZE)
    # print(key.hex())

    key = "7766554433221100"

    # iv = rand_bytes(SM4_CBC_IV_SIZE)
    # print(iv.hex())

    iv = "0011223344556677"

    # plaintext = 'abc'
    plaintext = "hello world"   // p7A0eCRSTovV4ZpK9hPxzQ==
    print("原始内容：" + plaintext)

    sm4_enc = Sm4Cbc(key.encode(), iv.encode(), DO_ENCRYPT)
    ciphertext = sm4_enc.update(plaintext.encode())
    ciphertext += sm4_enc.finish()

    print(plaintext + " 经过SM4 CBC加密后（HEX）：" + ciphertext.hex())

    print(base64.b64encode(bytes.fromhex(ciphertext.hex())).decode())

    print(plaintext + " 经过SM4 CBC加密后（Base64）：" + base64.b64encode(ciphertext).decode("utf-8"))

    sm4_dec = Sm4Cbc(key.encode(), iv.encode(), DO_DECRYPT)
    decrypted = sm4_dec.update(ciphertext)
    decrypted += sm4_dec.finish()

    print(decrypted.hex())
    print(bytes.fromhex(decrypted.hex()).decode("utf-8"))

    print(decrypted.decode("utf-8"))

def main():
    sm4CBC()

if __name__ == '__main__':
    main()