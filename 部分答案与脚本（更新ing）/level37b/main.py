import time
import secrets
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============ 配置 ============
BASE = "https://127.0.0.1:8443"
PATH = "/api/l37b"
DEV  = "android-29"                 # 参与签名，必须是真实设备标签
HEADERS = {
    "User-Agent": "Fatdog/1.0 (Android)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}

TOTAL_PAGES = 100


# ============ 魔改 MD5 实现（level37b）============
import struct
import hashlib

T = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
]
S = [
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5,9,14,20, 5,9,14,20, 5,9,14,20, 5,9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
]


def _md5_variant(data: bytes, k_table, iv) -> bytes:
    A, B, C, D = iv
    msg = bytearray(data)
    orig_len = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('<Q', orig_len)

    for off in range(0, len(msg), 64):
        M = list(struct.unpack('<16I', msg[off:off+64]))
        a, b, c, d = A, B, C, D
        for i in range(64):
            if i < 16:
                f = (b & c) | (~b & d); g = i
            elif i < 32:
                f = (d & b) | (~d & c); g = (5*i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d; g = (3*i + 5) % 16
            else:
                f = c ^ (b | ~d); g = (7*i) % 16
            f = (f + a + k_table[i] + M[g]) & 0xFFFFFFFF
            a = d; d = c; c = b
            b = (b + ((f << S[i]) | (f >> (32 - S[i])))) & 0xFFFFFFFF
        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF

    return struct.pack('<4I', A, B, C, D)


def _build_37b():
    iv1_bytes = hashlib.md5(b"Fatdog_blot|iv").digest()
    iv1 = struct.unpack('<4I', iv1_bytes)
    k = T[:]
    for idx in (5, 23, 41):
        k[idx] ^= 0x5A5A5A5A
    return iv1, k


_IV1, _K_MOD = _build_37b()


def sign_37b(payload: str) -> str:
    return _md5_variant(payload.encode('utf-8'), _K_MOD, _IV1).hex()


# ============ 生成一次请求 ============
def make_request(page: int):
    ts = int(time.time())
    nonce = secrets.token_hex(4)                     # 8 字符 hex，参与签名
    payload = f"dev={DEV}|nonce={nonce}|page={page}|ts={ts}"
    sign = sign_37b(payload)

    params = {
        "dev":   DEV,
        "nonce": nonce,
        "page":  page,
        "ts":    ts,
        "sign":  sign,
    }
    return params


# ============ 主流程 ============
def main():
    total = 0

    for page in range(1, TOTAL_PAGES + 1):
        params = make_request(page)

        try:
            r = requests.get(
                f"{BASE}{PATH}",
                params=params,
                headers=HEADERS,
                verify=False,          # 自签证书，跳过校验
                timeout=10,
            )

            try:
                nums = r.json()["nums"]
                total += sum(nums)
                print(f"[{page:3d}/{TOTAL_PAGES}] status={r.status_code} "
                      f"sum={sum(nums)} sign={params['sign'][:8]}...")
            except Exception as e:
                print(f"[{page:3d}/{TOTAL_PAGES}] status={r.status_code} "
                      f"resp={r.text[:200]} err={type(e).__name__}")

        except Exception as e:
            print(f"[{page:3d}/{TOTAL_PAGES}] 请求失败: {type(e).__name__} {e}")



    print("总和:", total)


if __name__ == "__main__":
    main()