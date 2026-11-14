import hashlib
import time
import requests
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
BASE = "https://127.0.0.1:8443"
PATH = "/api/l50"
KEY = b"Fatdog_abys_2026"
TOTAL_PAGES = 100

HEADERS = {
    "User-Agent": "okhttp/4.12.0",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}

def aes_encrypt(data: str) -> str:
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(data.encode(), 16)).hex()

def make_request(page: int):
    ts = int(time.time())
    body = f"page={page}&ts={ts}"
    enc_hex = aes_encrypt(body)
    sign_val = hashlib.sha256(enc_hex.encode()).hexdigest()
    return {"enc": enc_hex, "sign": sign_val, "ts": ts}

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