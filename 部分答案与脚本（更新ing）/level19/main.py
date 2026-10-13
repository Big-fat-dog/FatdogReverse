import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import requests
import hmac
import hashlib


def hmac_sha256_hex(message: str, key: str = 'fatdemo_hmac_key') -> str:
    """
    HmacSHA256 签名，返回 hex 字符串
    :param message: 待签名字符串
    :param key: 密钥，默认 "HmacSHA256"
    :return: 64 位小写 hex
    """
    if isinstance(message, str):
        message = message.encode("utf-8")
    if isinstance(key, str):
        key = key.encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()



def aes_ecb_pkcs5_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    AES/ECB/PKCS5Padding 加密
    :param plaintext: 明文字节
    :param key: 密钥字节，长度 16/24/32
    :return: 密文字节
    """
    cipher = AES.new(key, AES.MODE_ECB)
    # AES 块大小 16 字节，Java 的 PKCS5Padding 在 AES 下实际等同 PKCS7
    return cipher.encrypt(pad(plaintext, AES.block_size))


def aes_ecb_pkcs5_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    AES/ECB/PKCS5Padding 解密
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


def aes_ecb_pkcs5_encrypt_hex(plaintext_hex: str, key: bytes) -> str:
    """
    输入输出都是 hex 字符串的加密
    """
    plaintext = bytes.fromhex(plaintext_hex)
    ciphertext = aes_ecb_pkcs5_encrypt(plaintext, key)
    return ciphertext.hex()


def aes_ecb_pkcs5_decrypt_hex(ciphertext_hex: str, key: bytes) -> str:
    """
    输入输出都是 hex 字符串的解密
    """
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext = aes_ecb_pkcs5_decrypt(ciphertext, key)
    return plaintext.hex()


def decrypt_response(res_hex):
    cipher = AES.new(b'fatdemo_rspkey19', AES.MODE_ECB)
    return unpad(cipher.decrypt(bytes.fromhex(res_hex)), AES.block_size).decode()

def get_enc(i,t):
    key = bytes.fromhex("66617464656d6f5f6165736b65793139")
    msg = f"page=" + str(i) + "&ts="+str(t)
    return aes_ecb_pkcs5_encrypt_hex(msg.encode().hex(),key)

def get_sign(enc):
    result = hmac_sha256_hex(enc)
    return result


def post_api_l19(i):
    t = str(int(time.time()))
    url = "http://127.0.0.1:8787/api/l19"

    headers = {
        "User-Agent": "Fatdemo/1.0 (Android)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
    }

    enc = get_enc(i, t)
    sign = get_sign(enc)

    data = {
        "page": i,
        "ts": t,
        "enc": enc,
        "sign": sign,
        "client": "android-fatdemo",
        "chan": "ctf",
        "ver": "1.9",
        "dev": "0000000000000000",
    }

    resp = requests.post(url, headers=headers, data=data, timeout=10)
    res_hex = resp.json()['d']
    clear = decrypt_response(res_hex)
    return clear


def parse_nums(clear):
    """
    解析 'page=1|nums=18,94,72,...' 里的 nums 列表
    """
    # clear.split('|') -> ['page=1', 'nums=18,94,...']
    nums_str = clear.split('|')[1].split('=')[1]
    return [int(x) for x in nums_str.split(',') if x]
if __name__ == "__main__":
    total = 0
    for i in range(1, 101):
        clear = post_api_l19(i)
        nums = parse_nums(clear)
        page_sum = sum(nums)
        total += page_sum
        print(f"page={i:>3}  sum={page_sum:>5}  nums={nums}")

    print("total =", total)