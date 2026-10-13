import hashlib
import hmac
import struct
import time
import requests
import urllib3

from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
from Crypto.Cipher import DES3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============ 配置 ============
HOST = "127.0.0.1:8443"
PATH = "/api/l35"

CLIENT_CERT = r"D:\AppSpider\FatdogReverse\cert\ca.crt"
CLIENT_KEY  = r"D:\AppSpider\FatdogReverse\cert\ca.key"

TOTAL_PAGES = 100

# ============ 密钥派生 ============
SM4_KEY  = hashlib.sha256(b"Fatdog_sneak|sm4").digest()[:16]
DES3_KEY = hashlib.sha256(b"Fatdog_sneak|3des").digest()[:24]
SIGN_KEY = b"Fatdog_sneak"


# ============ 加密 ============
def sm4_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """SM4-ECB + 零填充"""
    pad_len = (16 - len(data) % 16) % 16
    data = data + b"\x00" * pad_len

    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(key, SM4_ENCRYPT)

    out = b""
    for i in range(0, len(data), 16):
        out += bytes(crypt_sm4.one_round(crypt_sm4.sk, data[i:i + 16]))
    return out


def des3_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """3DES-ECB，NoPadding"""
    return DES3.new(key, DES3.MODE_ECB).encrypt(data)


# ============ 构造请求 ============
def build_payload(page: int, ts: int = None) -> dict:
    if ts is None:
        ts = int(time.time())

    # e1 = SM4-ECB("page={page}&ts={ts}")
    e1_plain = f"page={page}&ts={ts}".encode()
    e1 = sm4_ecb_encrypt(SM4_KEY, e1_plain).hex()

    # e2 = 3DES-ECB(bswap64(ts))
    e2_plain = struct.pack(">Q", ts)
    e2 = des3_ecb_encrypt(DES3_KEY, e2_plain).hex()

    # sign = HMAC-SHA256(SIGN_KEY, "e1|e2")
    sign_msg = f"{e1}|{e2}".encode()
    sign = hmac.new(SIGN_KEY, sign_msg, hashlib.sha256).hexdigest()

    return {
        "page": str(page),
        "ts": str(ts),
        "e1": e1,
        "e2": e2,
        "sign": sign,
    }


# ============ 请求 ============
def make_session() -> requests.Session:
    s = requests.Session()
    s.trust_env = False
    s.cert = (CLIENT_CERT, CLIENT_KEY)
    s.verify = False
    s.headers.update({
        "User-Agent": "Fatdog/1.0 (Android)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
    })
    return s


def fetch_page(session: requests.Session, page: int):
    payload = build_payload(page)
    url = f"https://{HOST}{PATH}"
    return session.post(url, data=payload, timeout=10)


def main():
    session = make_session()
    grand_total = 0

    for page in range(1, TOTAL_PAGES + 1):
        try:
            resp = fetch_page(session, page)
            body = resp.text
            print(f"[{page:3d}/{TOTAL_PAGES}] status={resp.status_code} resp={body[:120]}")

            try:
                j = resp.json()
                nums = j.get("nums", [])
                if nums:
                    grand_total += sum(nums)
            except Exception:
                pass

        except Exception as e:
            print(f"[{page:3d}/{TOTAL_PAGES}] 失败: {type(e).__name__} {e}")
        time.sleep(0.05)

    print("=" * 60)
    print(f"总和: {grand_total}")


if __name__ == "__main__":
    main()