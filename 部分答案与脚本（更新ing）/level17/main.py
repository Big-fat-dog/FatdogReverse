import requests
import time
from gmssl import sm3
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT




def sm4_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """SM4/ECB/PKCS7 加密"""
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(key, SM4_ENCRYPT)
    return crypt_sm4.crypt_ecb(plaintext)

def sm4_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """SM4/ECB/PKCS7 解密（gmssl 内部自动去填充）"""
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(key, SM4_DECRYPT)
    return crypt_sm4.crypt_ecb(ciphertext)     # 直接解密，不要手动 unpad

def get_enc(data):
    key = "fatdemo_form_key".encode()
    data = data.encode('utf8')
    return sm4_ecb_encrypt(key, data).hex()

def get_sig(data):
    str1 = get_enc(data)
    str2 = "fatdemo_sm3_salt"
    msg = str1 + str2
    # 关键：转成 list[int]
    msg_list = list(msg.encode('utf-8'))
    result = sm3.sm3_hash(msg_list)
    return result

def get_res(data):
    key = "fatdemo_resp_key".encode()
    data = bytes.fromhex(data)
    res = sm4_ecb_decrypt(key, data)
    return res

url = "http://127.0.0.1:8787/api/form"
sum = 0

for i in range(1,101):
    t = str(int(time.time()))
    msg = "page=" + str(i) + "&ts=" + t
    data = {
        "page": i,
        "ts": t,
        "dog": "fatdog",
        "enc": get_enc(msg),
        "sig": get_sig(msg),
    }
    print(data)
    headers = {
        "User-Agent": "Fatdemo/1.0 (Android)",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    resp = requests.post(url, data=data, headers=headers)
    res = resp.json()["d"]
    target = get_res(res)
    target = target.decode('utf8')
    nums = [int(x) for x in str(target).split('nums=')[1].split(',')]
    for num in nums:
        sum += num
print(sum)