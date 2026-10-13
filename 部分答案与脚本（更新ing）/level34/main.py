import hashlib
import hmac
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============ 配置 ============
HOST = "127.0.0.1:8443"
PATH = "/api/l34"

KEY = b"Fatdog_grumpy"                      # HMAC 签名密钥
RSP = hashlib.sha256(b"Fatdog_grumpy|rsp").digest()[:16]  # RC4 密钥 = SHA256(...)[:16]

CLIENT_CERT = r"D:\AppSpider\FatdogReverse\cert\ca.crt"
CLIENT_KEY  = r"D:\AppSpider\FatdogReverse\cert\ca.key"

TOTAL_PAGES = 100

# ============ 请求侧：Feistel 加密 ============
SUBS = [hashlib.sha256(KEY + str(i).encode()).digest()[:4] for i in range(8)]


def F(i: int, x: bytes) -> bytes:
    return hashlib.sha256(SUBS[i] + x).digest()[:4]


def feistel_enc(data: bytes) -> bytes:
    out = bytearray()
    for off in range(0, len(data), 8):
        L, R = data[off:off + 4], data[off + 4:off + 8]
        for i in range(8):
            L, R = R, bytes(a ^ b for a, b in zip(L, F(i, R)))
        out += L + R
    return bytes(out)


def native_pack(page: int, ts: int) -> str:
    s = f"page={page}&ts={ts}".encode()
    pad = (-len(s)) % 8
    buf = s + b"\x00" * pad
    return feistel_enc(buf).hex()


# ============ 响应侧：标准 RC4 解密 ============
def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]

    out = bytearray(len(data))
    a = b = 0
    for k in range(len(data)):
        a = (a + 1) & 0xFF
        b = (b + S[a]) & 0xFF
        S[a], S[b] = S[b], S[a]
        out[k] = data[k] ^ S[(S[a] + S[b]) & 0xFF]
    return bytes(out)


def rc4_decrypt(hex_str: str) -> str:
    cipher = bytes.fromhex(hex_str)
    plain = rc4(RSP, cipher)
    return plain.decode("utf-8", errors="replace")


# ============ sign 生成 ============
def make_sign(enc: str) -> str:
    return hmac.new(KEY, enc.encode("ascii"), hashlib.sha256).hexdigest()


# ============ 请求 ============
def make_session() -> requests.Session:
    s = requests.Session()
    s.trust_env = False
    s.cert = (CLIENT_CERT, CLIENT_KEY)
    s.verify = False
    s.headers.update({
        "User-Agent": "Fatdog/1.0 (Android)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip",
    })
    return s


def fetch_page(session: requests.Session, page: int):
    ts = int(time.time())
    enc = native_pack(page, ts)
    sign = make_sign(enc)

    data = {
        "page": str(page),
        "ts": str(ts),
        "enc": enc,
        "sign": sign,
        "dev": "fatdog-sim",
        "ver": "3.4",
    }

    url = f"https://{HOST}{PATH}"
    return session.post(url, data=data, timeout=10)


# ============ 主流程 ============
def main():
    session = make_session()
    total = 0

    for page in range(1, TOTAL_PAGES + 1):
        try:
            resp = fetch_page(session, page)
            body = resp.text

            plain = None
            try:
                j = resp.json()
                if "d" in j:
                    plain = rc4_decrypt(j["d"])
            except Exception:
                pass

            if plain is not None:
                print(f"[{page:3d}/{TOTAL_PAGES}] status={resp.status_code} 明文={plain[:200]}")

                # 按标答格式累加：body.split("|")[1][5:].split(",")
                try:
                    part = plain.split("|")[1][5:]
                    total += sum(int(x) for x in part.split(",") if x.strip())
                except Exception as e:
                    print(f"    解析失败: {type(e).__name__} {e}")
            else:
                print(f"[{page:3d}/{TOTAL_PAGES}] status={resp.status_code} resp={body[:120]}")

        except Exception as e:
            print(f"[{page:3d}/{TOTAL_PAGES}] 失败: {type(e).__name__} {e}")

        time.sleep(0.05)

    print("总和:", total)


if __name__ == "__main__":
    main()