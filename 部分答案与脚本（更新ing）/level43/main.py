import hashlib
import hmac
import time
import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============ 配置 ============
HOST = "127.0.0.1:8443"
PATH = "/api/l43"

CLIENT_CERT = r"D:\AppSpider\FatdogReverse\cert\ca.crt"
CLIENT_KEY  = r"D:\AppSpider\FatdogReverse\cert\ca.key"

TOTAL_PAGES = 100

# ============ 签名密钥前缀 ============
SIGN_KEY_PREFIX = b"Fatdog_scan|"


# ============ vt 生成 ============
def new_vt() -> str:
    """8 字节随机数 -> 16 位小写 hex"""
    return os.urandom(8).hex()


# ============ 签名 ============
def sign_for(page: int, ts: int, vt: str) -> str:
    # key_raw = "Fatdog_scan|" + vt  (字符串)
    key_raw = "Fatdog_scan|" + vt

    # sha256Of(...) 返回 hex 字符串，作为 HMAC key 的 bytes
    hmac_key = hashlib.sha256(key_raw.encode()).hexdigest().encode()

    # HMAC message = "page={page}&ts={ts}"
    sign_msg = f"page={page}&ts={ts}".encode()

    return hmac.new(hmac_key, sign_msg, hashlib.sha256).hexdigest()


# ============ 构造请求参数 ============
def build_params(page: int, ts: int = None) -> dict:
    if ts is None:
        ts = int(time.time())

    vt = new_vt()
    sign = sign_for(page, ts, vt)

    return {
        "page": str(page),
        "ts": str(ts),
        "vt": vt,
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
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
    })
    return s


def fetch_page(session: requests.Session, page: int):
    params = build_params(page)
    url = f"https://{HOST}{PATH}"
    return session.get(url, params=params, timeout=10)


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


    print("=" * 60)
    print(f"总和: {grand_total}")


if __name__ == "__main__":
    main()