import hashlib
import hmac
import time
import requests
import urllib3
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============ 配置 ============
BASE = "https://127.0.0.1:8443"
PATH = "/api/l49"
HEADERS = {
    "User-Agent": "okhttp/4.12.0",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/x-www-form-urlencoded",
}

TOTAL_PAGES = 100

SM4_KEY  = b"Fatdog_mist_2026"       # "Fatdog_mist_" + mistTail() = "2026"
HMAC_KEY = b"Fatdog_forest_2026"     # forestHead() = "Fatdog_forest_" + "2026"


# ============ SM4 加密 ============
def sm4_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    cipher = CryptSM4()
    cipher.set_key(key, SM4_ENCRYPT)
    # gmssl 的 crypt_ecb 默认使用 PKCS#7 填充
    return cipher.crypt_ecb(data)


# ============ 签名 ============
def sign(enc_hex: str) -> str:
    # 对 enc 的 hex 字符串做 HMAC-MD5
    return hmac.new(HMAC_KEY, enc_hex.encode(), hashlib.md5).hexdigest()


# ============ 生成一次请求 ============
def make_request(page: int):
    ts = int(time.time())
    body = f"page={page}&ts={ts}"

    enc_bytes = sm4_ecb_encrypt(SM4_KEY, body.encode())
    enc_hex = enc_bytes.hex()

    sign_val = sign(enc_hex)

    data = {
        "enc":  enc_hex,
        "sign": sign_val,
        "algo": 0,
    }
    return data


# ============ 主流程 ============
def main():
    total = 0

    for page in range(1, TOTAL_PAGES + 1):
        data = make_request(page)

        try:
            r = requests.post(
                f"{BASE}{PATH}",
                data=data,
                headers=HEADERS,
                verify=False,                        # 本地自签证书，跳过校验
                timeout=10,
            )

            try:
                nums = r.json()["nums"]
                total += sum(nums)
                print(f"[{page:3d}/{TOTAL_PAGES}] status={r.status_code} "
                      f"sum={sum(nums)} sign={data['sign'][:8]}...")
            except Exception as e:
                print(f"[{page:3d}/{TOTAL_PAGES}] status={r.status_code} "
                      f"resp={r.text[:200]} err={type(e).__name__}")

        except Exception as e:
            print(f"[{page:3d}/{TOTAL_PAGES}] 请求失败: {type(e).__name__} {e}")

    print("总和:", total)


if __name__ == "__main__":
    main()