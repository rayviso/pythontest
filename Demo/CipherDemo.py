import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import time

# 定义固定密钥和测试数据（避免每次生成）
@pytest.fixture(scope="session")
def key16():
    return os.urandom(16)  # AES-128 密钥

@pytest.fixture(scope="session")
def key32():
    return os.urandom(32)  # AES-256 密钥

@pytest.fixture(scope="session")
def data():
    return os.urandom(1024 * 1024 * 1024)  # 调整为 1MB 数据（避免内存不足）

# 测试函数
def test_cbc_128_perf(key16, data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key16), modes.CBC(iv))
    encryptor = cipher.encryptor()

    start = time.time()
    encrypted = encryptor.update(data) + encryptor.finalize()
    duration = time.time() - start

    print(f"\nAES-CBC-128 加密耗时: {duration:.2f} 秒")

def test_cbc_256_perf(key32, data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key32), modes.CBC(iv))
    encryptor = cipher.encryptor()

    start = time.time()
    encrypted = encryptor.update(data) + encryptor.finalize()
    duration = time.time() - start

    print(f"\nAES-CBC-256 加密耗时: {duration:.2f} 秒")

def test_gcm_128_perf(key16, data):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key16), modes.GCM(nonce))
    encryptor = cipher.encryptor()

    start = time.time()
    encrypted = encryptor.update(data) + encryptor.finalize()
    duration = time.time() - start

    print(f"\nAES-GCM-128 加密耗时: {duration:.2f} 秒")

def test_gcm_256_perf(key32, data):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key32), modes.GCM(nonce))
    encryptor = cipher.encryptor()

    start = time.time()
    encrypted = encryptor.update(data) + encryptor.finalize()
    duration = time.time() - start

    print(f"\nAES-GCM-256 加密耗时: {duration:.2f} 秒")