from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import time
import requests
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def rsa(msg):
    # 1. 构造公钥
    n = int("122172802591289152926439503646879905201324426743244768088977100390063829994402005304613686375076247799395594432078512492000046231351895829781835897220617105966306984169075850976453613671680578573017757802207966384637092793163410880565667595906308645399416739381314554185341363069816689258343276055464775528269")
    e = 65537
    pub_key = RSA.construct((n, e))

    # 2. 加密
    cipher = PKCS1_v1_5.new(pub_key)
    plaintext = msg.encode('utf-8')
    ciphertext = cipher.encrypt(plaintext)

    # 3. 输出十六进制
    return ciphertext.hex()

def des_ecb_decrypt(ciphertext: bytes) -> bytes:
    key = b'ds18key!'
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), 8)


def get_res():
    pass

sum=0
url = "http://127.0.0.1:8787/api/rsa"
for i in range(1,101):
    t = str(int(time.time()))
    msg = "page=" + str(i) + "&ts=" + t
    data = {
        "page": i,
        "ts": t,
        "enc": rsa(msg),
        "client": "android-fatdemo",
        "chan": "ctf",
        "ver": "1.8",
        "dev": "0000000000000000",
    }
    headers = {
        "User-Agent": "Fatdemo/1.0 (Android)",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    resp = requests.post(url, data=data, headers=headers)
    res = resp.json()["d"]
    msgs = bytes.fromhex(res)
    target = des_ecb_decrypt(msgs)
    target = target.decode('utf8')
    nums = [int(x) for x in str(target).split('nums=')[1].split(',')]
    for num in nums:
        sum += num
print(sum)
    #解密走的是DES
