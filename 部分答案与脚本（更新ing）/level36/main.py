import base64
import hashlib
import hmac
import time

import requests
import urllib3
from Crypto.Cipher import AES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============ 配置 ============
BASE = "https://127.0.0.1:8443"
PATH = "/api/l36"

# 客户端证书（双向 TLS）
CLIENT_CERT = r"D:\AppSpider\FatdogReverse\cert\ca.crt"
CLIENT_KEY  = r"D:\AppSpider\FatdogReverse\cert\ca.key"

# AES 主密钥：Base64 解码 "tE5zEyf1b+fe49uJN4cY7w=="
AES_KEY = base64.b64decode("tE5zEyf1b+fe49uJN4cY7w==")
assert len(AES_KEY) == 16, f"AES key length = {len(AES_KEY)}"

# HMAC 密钥：SHA256("Fatdog_break|mac") 完整 32 字节
MAC_KEY = hashlib.sha256(b"Fatdog_break|mac").digest()

TOTAL_PAGES = 100


# ============ enc 生成：AES-128-ECB + ZeroPadding ============
def native_pack(page: int, ts: int) -> str:
    """page 和 ts 的格式化字符串 → AES-128-ECB（ZeroPadding）→ hex"""
    payload = f"page={page}&ts={ts}".encode()
    payload += b"\x00" * ((-len(payload)) % 16)          # ZeroPadding 到 16 字节对齐
    enc = AES.new(AES_KEY, AES.MODE_ECB).encrypt(payload)
    return enc.hex()


# ============ sign 生成：HMAC-SHA256(key, enc) ============
def make_sign(enc: str) -> str:
    """HMAC-SHA256，密钥 SHA256('Fatdog_break|mac')，消息为 enc 字符串"""
    return hmac.new(MAC_KEY, enc.encode(), hashlib.sha256).hexdigest()


# ============ 主流程 ============
def main():
    total = 0

    for page in range(1, TOTAL_PAGES + 1):
        ts = int(time.time())
        enc = native_pack(page, ts)
        sign = make_sign(enc)

        try:
            r = requests.get(
                f"{BASE}{PATH}",
                params={"page": page, "ts": ts, "enc": enc, "sign": sign},
                cert=(CLIENT_CERT, CLIENT_KEY),   # 客户端证书（双向 TLS）
                verify=False,                     # 跳过服务端证书校验
                timeout=10,
            )

            try:
                nums = r.json()["nums"]
                total += sum(nums)
                print(f"[{page:3d}/{TOTAL_PAGES}] status={r.status_code} sum={sum(nums)}")
            except Exception as e:
                print(f"[{page:3d}/{TOTAL_PAGES}] status={r.status_code} "
                      f"resp={r.text[:200]} err={type(e).__name__}")

        except Exception as e:
            print(f"[{page:3d}/{TOTAL_PAGES}] 请求失败: {type(e).__name__} {e}")

        time.sleep(0.05)

    print("总和:", total)


if __name__ == "__main__":
    main()