import hmac
import hashlib
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

KEY = b"Fatdog_lonely"
HOST = "127.0.0.1:8443"
PATH = "/api/l31"

CLIENT_CERT = r"D:\AppSpider\FatdogReverse\cert\ca.crt"
CLIENT_KEY  = r"D:\AppSpider\FatdogReverse\cert\ca.key"

TOTAL_PAGES = 100


# ============ 核心算法 ============

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def gen_enc(page: int, ts: int) -> str:
    plain = f"page={page}&ts={ts}".encode()
    return rc4(KEY, plain).hex()


def gen_sign(enc: str) -> str:
    return hmac.new(KEY, enc.encode(), hashlib.sha256).hexdigest()


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


def fetch_page(session: requests.Session, page: int) -> list:
    ts = int(time.time())
    enc = gen_enc(page, ts)
    sign = gen_sign(enc)

    data = {
        "page": page,
        "ts": ts,
        "enc": enc,
        "sign": sign,
    }

    url = f"https://{HOST}{PATH}"
    resp = session.post(url, data=data, timeout=10)
    resp.raise_for_status()
    result = resp.json()
    return result.get("nums", [])


# ============ 主流程 ============

def main():
    session = make_session()

    grand_total = 0
    per_page = []

    for page in range(1, TOTAL_PAGES + 1):
        try:
            nums = fetch_page(session, page)
            s = sum(nums)
            grand_total += s
            per_page.append((page, nums, s))
            print(f"[{page:3d}/{TOTAL_PAGES}] nums={nums} sum={s}")
        except Exception as e:
            print(f"[{page:3d}/{TOTAL_PAGES}] 失败: {type(e).__name__} {e}")
        time.sleep(0.05)

    print("=" * 60)
    print(f"总页数: {TOTAL_PAGES}")
    print(f"每页和的总和: {grand_total}")


if __name__ == "__main__":
    main()