from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad,unpad
import hashlib
import time
import requests
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad




urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
BASE = "https://127.0.0.1:8443"
PATH = "/api/l51"

TOTAL_PAGES = 100

HEADERS = {
    "User-Agent": "okhttp/4.12.0",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}
def des3_encrypt(plaintext):
    key= "Fatdog_thunder_2026"
    key=key.encode("utf8")+b"\x00" * 5
    plaintext=pad(plaintext.encode(),8)
    # 初始化加密器
    cipher = DES3.new(key, DES3.MODE_ECB)
    # 加密
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()
def sm(data):
    data="Fatdog_peak_salt!"+data
    hasher = hashlib.new('sm3')  # 激活SM3算法
    hasher.update(data.encode('utf-8'))
    hash_value = hasher.hexdigest()
    return hash_value # 输出64位十六进制哈希值


def make_request(page: int):
    ts = int(time.time())
    body = f"page={page}&ts={ts}"
    enc_hex = des3_encrypt(body)
    sign_val = sm(enc_hex)
    return {"enc": enc_hex, "sig": sign_val, "ts": ts}

def main():
    total = 0
    for page in range(1, TOTAL_PAGES + 1):
        params = make_request(page)
        try:
            r = requests.get(
                f"{BASE}{PATH}",
                params=params,
                headers=HEADERS,
                verify=False,
                timeout=10,
            )
            nums = r.json()["nums"]
            total += sum(nums)
            print(f"[{page:3d}/{TOTAL_PAGES}] status={r.status_code} sum={sum(nums)}")
        except Exception as e:
            print(f"[{page:3d}/{TOTAL_PAGES}] status={r.status_code} resp={r.text[:200]} err={type(e).__name__}")
    print("总和:", total)

if __name__ == "__main__":
    main()