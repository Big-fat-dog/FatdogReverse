# -*- coding: utf-8 -*-
"""FatdogReverse 本地模拟服务端（FastAPI 版，对齐 demo1 结构）——数字只在这里，APK 里一个都没有。

  HTTP      : http://0.0.0.0:8787   （关卡 15-20）
  HTTPS     : https://0.0.0.0:8443  （关卡 21-25、27，自签 CA）
  HTTPS-mTLS: https://0.0.0.0:8444  （关卡 26，双向 TLS：强制客户端证书，独立 app 实例防跨端口绕过）

依赖：pip install fastapi uvicorn pycryptodome   (SM3/SM4/RC4 为纯 Python 实现，无需 gmssl)

启动：python server.py
"""
import hashlib
import hmac
import os
import random
import re
import threading
import time

from fastapi import FastAPI, HTTPException, Query, Form, Request
from fastapi.responses import HTMLResponse
import uvicorn

try:
    from Crypto.Cipher import AES as _AES, DES as _DES, PKCS1_v1_5
    from Crypto.PublicKey import RSA as _RSA
    from Crypto.Util.Padding import pad, unpad
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

HOST = "0.0.0.0"
PORT_HTTP = 8787
PORT_HTTPS = 8443
TS_WINDOW = 600

# ---------------- 关卡 15 ----------------
KEY = b"fatdemo_page_key_2026"
PAGES = 100
PER_PAGE = 10
SEED = 20260715
_rng = random.Random(SEED)
NUMS = [_rng.randint(1, 100) for _ in range(PAGES * PER_PAGE)]

# ---------------- 关卡 16：RC4 ----------------
KEY16_REQ = b"fatdemo_rc4_req_2026"
KEY16_RSP = b"fatdemo_rc4_rsp_2026"
SIG16_SALT = b"fatdemo_rc4_sig_salt"
PAGES16, PER_PAGE16, SEED16 = 60, 8, 20260816
_rng16 = random.Random(SEED16)
NUMS16 = [_rng16.randint(1, 100) for _ in range(PAGES16 * PER_PAGE16)]

# ---------------- 关卡 17：SM4 表单 ----------------
KEY17_REQ = b"fatdemo_form_key"
KEY17_RSP = b"fatdemo_resp_key"
SIG17_SALT = b"fatdemo_sm3_salt"
DOG17 = "fatdog"
PAGES17, PER_PAGE17, SEED17 = 100, 10, 20260901
_rng17 = random.Random(SEED17)
NUMS17 = [_rng17.randint(1, 100) for _ in range(PAGES17 * PER_PAGE17)]

# ---------------- 关卡 18：RSA + DES ----------------
KEY18_RSA_N = int("adfad72ed2b45844ab2f8a41c056836c58428b3673da423d9f1f8425d1ee895ea26f71c808b38f7b8839f9c8ace28478eb2f84b415930e10bb339023d83ee7cc9e5b89bcbf97f2b15d72a712727ed34d71d23d783b34aef3bc75f9cf5e1ea2c1db0547d9b3373a75e2116c11acc6d3f17e5e7bedccb5415079743aee417c2f4d", 16)
KEY18_RSA_D = int("1e143090c14ff9b4c18de20ed5147ffb42d51a616b2d30679bf3a472af75589d9a62bf1eb0d66e779289477498e33eb8f31c4f8a9cf2442bc359ba5160291c04fbe826030abfd55466fa9b74d789c72014286395710789f6608c4271ce9de48d91ea26e6a5eddef2e6596bb95ca81b5f3fb3691f17579e6edc646d90aeb4f387", 16)
KEY18_RSA_E = 65537
KEY18_DES = b"ds18key!"  # ds18 + key! 拼出完整 8 字节密钥
DES18_HALF_A_HEX = "64733138"  # "ds18"
PAGES18, PER_PAGE18, SEED18 = 100, 10, 20261001
_rng18 = random.Random(SEED18)
NUMS18 = [_rng18.randint(1, 100) for _ in range(PAGES18 * PER_PAGE18)]

# ---------------- 关卡 19：AES + HMAC ----------------
KEY19_AES_REQ = b"fatdemo_aeskey19"
KEY19_HMAC = b"fatdemo_hmac_key"
KEY19_AES_RSP = b"fatdemo_rspkey19"
PAGES19, PER_PAGE19, SEED19 = 100, 10, 20261016
_rng19 = random.Random(SEED19)
NUMS19 = [_rng19.randint(1, 100) for _ in range(PAGES19 * PER_PAGE19)]

# ---------------- 关卡 21：HTTPS + TrustManager ----------------
KEY21_HMAC = b"fatdemo_ssl_hmac"
PAGES21, PER_PAGE21, SEED21 = 100, 10, 20261102
_rng21 = random.Random(SEED21)
NUMS21 = [_rng21.randint(1, 100) for _ in range(PAGES21 * PER_PAGE21)]

# ---------------- 关卡 22：HTTPS + CertificatePinner ----------------
KEY22_HMAC = b"fatdemo_pin_key"
PAGES22, PER_PAGE22, SEED22 = 100, 10, 20261203
_rng22 = random.Random(SEED22)
NUMS22 = [_rng22.randint(1, 100) for _ in range(PAGES22 * PER_PAGE22)]

# ---------------- 关卡 24：反 Hook + 换票（内存换 pin） ----------------
KEY24_HMAC = b"fatdemo_swap_key"
PAGES24, PER_PAGE24, SEED24 = 100, 10, 20261224
_rng24 = random.Random(SEED24)
NUMS24 = [_rng24.randint(1, 100) for _ in range(PAGES24 * PER_PAGE24)]

# ---------------- 关卡 25：native 校验（JNI） ----------------
KEY25_HMAC = b"fatdemo_jni_2026"
PAGES25, PER_PAGE25, SEED25 = 100, 10, 20270115
_rng25 = random.Random(SEED25)
NUMS25 = [_rng25.randint(1, 100) for _ in range(PAGES25 * PER_PAGE25)]

# ---------------- 关卡 26：双向 TLS（mTLS，客户端证书） ----------------
KEY26_HMAC = b"fatdemo_mtls_key"
PAGES26, PER_PAGE26, SEED26 = 100, 10, 20270206
_rng26 = random.Random(SEED26)
NUMS26 = [_rng26.randint(1, 100) for _ in range(PAGES26 * PER_PAGE26)]

# ---------------- 关卡 27：万法归宗（HTTPS + pinning + 复合签名，复用 L19 那套） ----------------
KEY27_AES_REQ = b"fatdemo_aeskey27"
KEY27_HMAC = b"fatdemo_fin_hmac"
KEY27_AES_RSP = b"fatdemo_rspkey27"
PAGES27, PER_PAGE27, SEED27 = 100, 10, 20270227
_rng27 = random.Random(SEED27)
NUMS27 = [_rng27.randint(1, 100) for _ in range(PAGES27 * PER_PAGE27)]

# ---------------- 关卡 28：native 字符串加密（密钥异或藏 libl28.so，运行时解码） ----------------
KEY28_HMAC = b"Fatdog_unhappy"          # 自 L28 起启用 Fatdog_<情绪词> 标记
PAGES28, PER_PAGE28, SEED28 = 100, 10, 20270315
_rng28 = random.Random(SEED28)
NUMS28 = [_rng28.randint(1, 100) for _ in range(PAGES28 * PER_PAGE28)]

# ---------------- 关卡 29：native 动态注册（真身无名，导出表全是诱饵） ----------------
KEY29_HMAC = b"Fatdog_angry"
PAGES29, PER_PAGE29, SEED29 = 100, 10, 20270412
_rng29 = random.Random(SEED29)
NUMS29 = [_rng29.randint(1, 100) for _ in range(PAGES29 * PER_PAGE29)]

# ---------------- 关卡 30：无名剑冢（函数指针表派发，密钥 UTF-16 藏匿） ----------------
KEY30_HMAC = b"Fatdog_gloomy"
PAGES30, PER_PAGE30, SEED30 = 100, 10, 20270520
_rng30 = random.Random(SEED30)
NUMS30 = [_rng30.randint(1, 100) for _ in range(PAGES30 * PER_PAGE30)]

# ---------------- 关卡 31：两界穿针（跨层密钥 + 干扰包，POST 表单） ----------------
KEY31_HMAC = b"Fatdog_lonely"
DECOY31_KEYS = [b"Fatdog_lovely"]      # 近亲假钥：命中即点名 403
PAGES31, PER_PAGE31, SEED31 = 100, 10, 20270618
_rng31 = random.Random(SEED31)
NUMS31 = [_rng31.randint(1, 100) for _ in range(PAGES31 * PER_PAGE31)]

# ---------------- 关卡 32：心魔哨兵（native 反检测 + 静默投毒） ----------------
KEY32_HMAC = b"Fatdog_anxious"
PAGES32, PER_PAGE32, SEED32 = 100, 10, 20270726
_rng32 = random.Random(SEED32)
NUMS32 = [_rng32.randint(1, 100) for _ in range(PAGES32 * PER_PAGE32)]

# ---------------- 关卡 33：金刚不坏（CRC 自校验 + 记账守卫） ----------------
KEY33_HMAC = b"Fatdog_jealous"
PAGES33, PER_PAGE33, SEED33 = 100, 10, 20270901
_rng33 = random.Random(SEED33)
NUMS33 = [_rng33.randint(1, 100) for _ in range(PAGES33 * PER_PAGE33)]


# ---------------- 关卡 34：万法归墟（Feistel + HMAC + 响应 RC4，综合卷） ----------------
KEY34_HMAC = b"Fatdog_grumpy"
RSP34_KEY = hashlib.sha256(b"Fatdog_grumpy|rsp").digest()[:16]
PAGES34, PER_PAGE34, SEED34 = 100, 10, 20271015
_rng34 = random.Random(SEED34)
NUMS34 = [_rng34.randint(1, 100) for _ in range(PAGES34 * PER_PAGE34)]


# ---------------- 关卡 35：双匣暗渡（手写 3DES+SM4 + 干扰包） ----------------
KEY35_MASTER = b"Fatdog_sneak"
DECOY35_KEYS = [b"Fatdog_skulk"]
PAGES35, PER_PAGE35, SEED35 = 100, 10, 20271111
_rng35 = random.Random(SEED35)
NUMS35 = [_rng35.randint(1, 100) for _ in range(PAGES35 * PER_PAGE35)]

# ---------------- 关卡 37：雪崩之谜（SHA-256 变体 IV + RC4 叠加） ----------------
KEY37_MARKER = b"Fatdog_dodge"
DECOY37_KEYS = [b"Fatdog_drift"]
PAGES37, PER_PAGE37, SEED37 = 100, 10, 20271223
_rng37 = random.Random(SEED37)
NUMS37 = [_rng37.randint(1, 100) for _ in range(PAGES37 * PER_PAGE37)]

_K37_HEX = ("428a2f9871374491b5c0fbcfe9b5dba53956c25b59f111f1923f82a4ab1c5ed5"
            "d807aa9812835b01243185be550c7dc372be5d7480deb1fe9bdc06a7c19bf174"
            "e49b69c1efbe47860fc19dc6240ca1cc2de92c6f4a7484aa5cb0a9dc76f988da"
            "983e5152a831c66db00327c8bf597fc7c6e00bf3d5a7914706ca635114292967"
            "27b70a852e1b21384d2c6dfc53380d13650a7354766a0abb81c2c92e92722c85"
            "a2bfe8a1a81a664bc24b8b70c76c51a3d192e819d6990624f40e3585106aa070"
            "19a4c1161e376c082748774c34b0cb53391c0cb34ed8aa4a5b9cca4f682e6ff3"
            "748f82ee78a5636f84c878148cc7020890befffaa4506cebbef9a3f7c67178f2")
_K37_W = [int(_K37_HEX[i * 8:(i + 1) * 8], 16) for i in range(64)]
_STD_IV_W = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
             0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
_M37 = 0xFFFFFFFF


def _r37(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _M37


def sha37_iv(data: bytes, iv_words=None) -> bytes:
    """手写 SHA-256：压缩轮与标准一致；iv_words 缺省为标准 IV"""
    h = list(_STD_IV_W if iv_words is None else iv_words)
    msg = bytearray(data)
    ml = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += ml.to_bytes(8, "big")
    for off in range(0, len(msg), 64):
        w = [int.from_bytes(msg[off + i * 4:off + i * 4 + 4], "big") for i in range(16)]
        for i in range(16, 64):
            s0 = _r37(w[i - 15], 7) ^ _r37(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _r37(w[i - 2], 17) ^ _r37(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & _M37)
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            S1 = _r37(e, 6) ^ _r37(e, 11) ^ _r37(e, 25)
            ch = (e & f) ^ ((~e & _M37) & g)
            t1 = (hh + S1 + ch + _K37_W[i] + w[i]) & _M37
            S0 = _r37(a, 2) ^ _r37(a, 13) ^ _r37(a, 22)
            mj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + mj) & _M37
            ne = (d + t1) & _M37
            hh, g, f, e = g, f, e, ne
            d, c, b, a = c, b, a, (t1 + t2) & _M37
        h = [(x + y) & _M37 for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return b"".join(x.to_bytes(4, "big") for x in h)


def rc4_37(key: bytes, data: bytes) -> bytes:
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray(); a = b = 0
    for ch in data:
        a = (a + 1) % 256; b = (b + S[a]) % 256
        S[a], S[b] = S[b], S[a]
        out.append(ch ^ S[(S[a] + S[b]) % 256])
    return bytes(out)


IV37_B = sha37_iv(b"Fatdog_dodge|iv")                    # 换血后的 IV（32 字节）
IV37_W = [int.from_bytes(IV37_B[i * 4:i * 4 + 4], "big") for i in range(8)]
RC4K37 = sha37_iv(b"Fatdog_dodge|rc4")[:16]


def variant_sign_37(payload: bytes) -> str:
    dg = sha37_iv(payload, IV37_W)                       # 换血 IV 压缩
    return rc4_37(RC4K37, dg).hex()                      # 再叠一层 RC4


# FastAPI 主实例：必须先于所有 @app 路由装饰器创建
app = FastAPI(title="FatdogReverse 本地服务端", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/api/l37")
def api_l37(page: int = Query(...), ts: int = Query(...), sign: str = Query(...)):
    _check_ts(ts)
    expect = variant_sign_37(f"page={page}&ts={ts}".encode())
    if hmac.compare_digest(sign, expect):
        _check_page(page, PAGES37)
        idx = (page - 1) * PER_PAGE37
        return {"page": page, "nums": NUMS37[idx:idx + PER_PAGE37]}
    raise HTTPException(status_code=403, detail="sign invalid")

# ---------------- 关卡 36：查表识君（手写 AES-128 + Base64 藏钥） ----------------
KEY36_MASTER = b"Fatdog_break"
DECOY36_KEYS = [b"Fatdog_bluff"]
PAGES36, PER_PAGE36, SEED36 = 100, 10, 20271125
_rng36 = random.Random(SEED36)
NUMS36 = [_rng36.randint(1, 100) for _ in range(PAGES36 * PER_PAGE36)]


def _aes128_ecb_encrypt(key16: bytes, data: bytes) -> bytes:
    c = _AES.new(key16, _AES.MODE_ECB)
    return c.encrypt(data)


def _aes128_ecb_decrypt(key16: bytes, data: bytes) -> bytes:
    c = _AES.new(key16, _AES.MODE_ECB)
    return c.decrypt(data)


def _l36_try(master: str, page: int, ts: int, enc: str, sign: str) -> bool:
    mk = master.encode()
    akey = hashlib.sha256(mk + b"|key").digest()[:16]
    mack = hashlib.sha256(mk + b"|mac").digest()
    if not hmac.compare_digest(sign, hmac.new(mack, enc.encode(), hashlib.sha256).hexdigest()):
        return False
    try:
        p = _aes128_ecb_decrypt(akey, bytes.fromhex(enc))
        plain = p.split(b"\x00")[0].decode("utf-8", "ignore")
    except Exception:
        return False
    m = re.fullmatch(r"page=(\d+)&ts=(\d+)", plain or "")
    return bool(m) and int(m.group(1)) == page and int(m.group(2)) == ts


@app.get("/api/l36")
def api_l36(page: int = Query(...), ts: int = Query(...), enc: str = Query(...),
            sign: str = Query(...)):
    _check_ts(ts)
    if _l36_try("Fatdog_break", page, ts, enc, sign):
        _check_page(page, PAGES36)
        idx = (page - 1) * PER_PAGE36
        return {"page": page, "nums": NUMS36[idx:idx + PER_PAGE36]}
    for dk in DECOY36_KEYS:
        if _l36_try(dk, page, ts, enc, sign):
            raise HTTPException(status_code=403, detail="sign invalid")
    return {"page": page, "nums": []}


# ---------------- 关卡 43（KL6）冰封之钥：魔改 AES-128（Rcon 三处换血） ----------------
KEY43_MASTER = "Fatdog_pierce"
DECOY43_KEYS = ["Fatdog_piece"]
PAGES43, PER_PAGE43, SEED43 = 100, 10, 20280107
_rng43 = random.Random(SEED43)
NUMS43 = [_rng43.randint(1, 100) for _ in range(PAGES43 * PER_PAGE43)]

_SBOX43 = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
_RSBOX43 = [0] * 256
for _i, _v in enumerate(_SBOX43):
    _RSBOX43[_v] = _i
_RCON43 = [0x01, 0x02, 0x04, 0x9e, 0x10, 0x20, 0x77, 0x80, 0x1b, 0xd4]  # idx3/6/9 换血


def _xt(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)


def _gmul(a: int, b: int) -> int:
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = _xt(a)
        b >>= 1
    return r


def _inv_shift43(s: bytearray) -> None:
    t = s[1]
    s[1] = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = t
    s[2], s[10] = s[10], s[2]
    s[6], s[14] = s[14], s[6]
    t = s[3]
    s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t


def _key_expand_43(key16: bytes) -> list:
    rk = [bytearray(key16)]
    for i in range(1, 11):
        prev = rk[-1]
        cur = bytearray(16)
        t = [_SBOX43[prev[13]], _SBOX43[prev[14]], _SBOX43[prev[15]], _SBOX43[prev[12]]]
        t[0] ^= _RCON43[i - 1]
        for j in range(4):
            cur[j] = prev[j] ^ t[j]
        for j in range(4, 16):
            cur[j] = prev[j] ^ cur[j - 4]
        rk.append(cur)
    return rk


def aes43_ecb_decrypt(key16: bytes, data: bytes) -> bytes:
    """魔改 AES-128-ECB 解密（与 libm1.so 的手写实现互为镜像）"""
    rk = _key_expand_43(key16)
    out = b""
    for off in range(0, len(data), 16):
        s = bytearray(data[off:off + 16])
        for i in range(16):
            s[i] ^= rk[10][i]
        for r in range(9, 0, -1):
            _inv_shift43(s)
            for i in range(16):
                s[i] = _RSBOX43[s[i]]
            for i in range(16):
                s[i] ^= rk[r][i]
            for c in range(4):
                a0, a1, a2, a3 = s[4*c], s[4*c+1], s[4*c+2], s[4*c+3]
                s[4*c+0] = _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)
                s[4*c+1] = _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)
                s[4*c+2] = _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11)
                s[4*c+3] = _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14)
        _inv_shift43(s)
        for i in range(16):
            s[i] = _RSBOX43[s[i]]
        for i in range(16):
            s[i] ^= rk[0][i]
        out += bytes(s)
    return out


def _l43_try(master: str, page: int, ts: int, enc: str, sign: str) -> bool:
    mk = master.encode()
    akey = hashlib.sha256(mk + b"|aes").digest()[:16]
    mack = hashlib.sha256(mk + b"|mac").digest()
    if not hmac.compare_digest(sign, hmac.new(mack, enc.encode(), hashlib.sha256).hexdigest()):
        return False
    try:
        p = aes43_ecb_decrypt(akey, bytes.fromhex(enc))
        plain = p.split(b"\x00")[0].decode("utf-8", "ignore")
    except Exception:
        return False
    m = re.fullmatch(r"page=(\d+)&ts=(\d+)", plain or "")
    return bool(m) and int(m.group(1)) == page and int(m.group(2)) == ts


@app.get("/api/l43")
def api_l43(page: int = Query(...), ts: int = Query(...), enc: str = Query(...),
            sign: str = Query(...)):
    _check_ts(ts)
    if _l43_try(KEY43_MASTER, page, ts, enc, sign):
        _check_page(page, PAGES43)
        idx = (page - 1) * PER_PAGE43
        return {"page": page, "nums": NUMS43[idx:idx + PER_PAGE43]}
    for dk in DECOY43_KEYS:
        if _l43_try(dk, page, ts, enc, sign):
            raise HTTPException(status_code=403, detail="sign invalid")
    return {"page": page, "nums": []}


# ---------------- 关卡 44（KL7）裂魂之匣：魔改 DES（IP 首尾互换 + S3 换位 + FP 重算） ----------------
KEY44_MASTER = "Fatdog_shatter"
DECOY44_KEYS = ["Fatdog_scatter"]
PAGES44, PER_PAGE44, SEED44 = 100, 10, 20271115
_rng44 = random.Random(SEED44)
NUMS44 = [_rng44.randint(1, 100) for _ in range(PAGES44 * PER_PAGE44)]

_IP44 = [
    7, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 58,
]
_FP44 = [
    40, 8, 48, 16, 56, 24, 1, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 64, 41, 9, 49, 17, 57, 25,
]
_E44 = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
]
_PC144 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4,
]
_PC244 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
]
_SHIFTS44 = [
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
]
_P44 = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]
_S44 = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 9, 0, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
]

def _ks44(key8):
    bits = [(b >> (7 - i)) & 1 for b in key8 for i in range(8)]
    pc1 = [bits[t - 1] for t in _PC144]
    c, d = pc1[:28], pc1[28:]
    rks = []
    for s in _SHIFTS44:
        c = c[s:] + c[:s]
        d = d[s:] + d[:s]
        cd = c + d
        rks.append([cd[t - 1] for t in _PC244])
    return rks


def _blk44(blk, rks, enc=True):
    bits = [(b >> (7 - i)) & 1 for b in blk for i in range(8)]
    st = [bits[t - 1] for t in _IP44]
    l, r = st[:32], st[32:]
    order = range(16) if enc else range(15, -1, -1)
    for rnd in order:
        e = [r[t - 1] for t in _E44]
        x = [a ^ b for a, b in zip(e, rks[rnd])]
        o = []
        for i in range(8):
            b6 = x[i * 6:i * 6 + 6]
            row = (b6[0] << 1) | b6[5]
            col = (b6[1] << 3) | (b6[2] << 2) | (b6[3] << 1) | b6[4]
            v = _S44[i][row * 16 + col]
            o += [(v >> (3 - j)) & 1 for j in range(4)]
        f = [o[t - 1] for t in _P44]
        l, r = r, [a ^ b for a, b in zip(l, f)]
    pre = r + l
    ob = bytearray(8)
    fin = [pre[t - 1] for t in _FP44]
    for i, v in enumerate(fin):
        if v:
            ob[i >> 3] |= 0x80 >> (i & 7)
    return bytes(ob)


def des44_ede_decrypt(key24: bytes, data: bytes) -> bytes:
    """魔改 3DES-EDE 解密 p = D(K1, E(K2, D(K3, c)))，与 libm2.so 手写实现互为镜像"""
    k1, k2, k3 = _ks44(key24[:8]), _ks44(key24[8:16]), _ks44(key24[16:24])
    out = b""
    for off in range(0, len(data), 8):
        blk = data[off:off + 8]
        a = _blk44(blk, k3, enc=False)
        b = _blk44(a, k2, enc=True)
        out += _blk44(b, k1, enc=False)
    return out


def _l44_try(master: str, page: int, ts: int, enc: str, sign: str) -> bool:
    mk = master.encode()
    dk = hashlib.sha256(mk + b"|des").digest()[:24]
    mack = hashlib.sha256(mk + b"|mac").digest()
    if not hmac.compare_digest(sign, hmac.new(mack, enc.encode(), hashlib.sha256).hexdigest()):
        return False
    try:
        p = des44_ede_decrypt(dk, bytes.fromhex(enc))
        plain = p.split(b"\x00")[0].decode("utf-8", "ignore")
    except Exception:
        return False
    m = re.fullmatch(r"page=(\d+)&ts=(\d+)", plain or "")
    return bool(m) and int(m.group(1)) == page and int(m.group(2)) == ts


@app.post("/api/l44")
def api_l44(page: int = Form(...), ts: int = Form(...), enc: str = Form(...),
            sign: str = Form(...)):
    _check_ts(ts)
    if _l44_try(KEY44_MASTER, page, ts, enc, sign):
        _check_page(page, PAGES44)
        idx = (page - 1) * PER_PAGE44
        return {"page": page, "nums": NUMS44[idx:idx + PER_PAGE44]}
    for dk in DECOY44_KEYS:
        if _l44_try(dk, page, ts, enc, sign):
            raise HTTPException(status_code=403, detail="sign invalid")
    return {"page": page, "nums": []}


def _des3_ecb_encrypt_py(key24: bytes, data8: bytes) -> bytes:
    d1 = _DES.new(key24[0:8], _DES.MODE_ECB)
    d2 = _DES.new(key24[8:16], _DES.MODE_ECB)
    d3 = _D.new(key24[16:24], _DES.MODE_ECB)
    return d3.encrypt(d2.decrypt(d1.encrypt(data8)))


def _des3_ecb_decrypt_py(key24: bytes, data8: bytes) -> bytes:
    d1 = _DES.new(key24[0:8], _DES.MODE_ECB)
    d2 = _DES.new(key24[8:16], _DES.MODE_ECB)
    d3 = _D.new(key24[16:24], _DES.MODE_ECB)
    return d1.decrypt(d2.encrypt(d3.decrypt(data8)))


def _l35_try(master: str, page: int, ts: int, e1: str, e2: str, sign: str) -> bool:
    mk = master.encode()
    smk = hashlib.sha256(mk + b"|sm4").digest()[:16]
    dsk = hashlib.sha256(mk + b"|3des").digest()[:24]
    if not hmac.compare_digest(sign, hmac.new(mk, (e1 + "|" + e2).encode(), hashlib.sha256).hexdigest()):
        return False
    try:
        p = sm4_decrypt(smk, bytes.fromhex(e1))
        plain = p.split(b"\x00")[0].decode("utf-8", "ignore")
    except Exception:
        return False
    m = re.fullmatch(r"page=(\d+)&ts=(\d+)", plain or "")
    if not m or int(m.group(1)) != page or int(m.group(2)) != ts:
        return False
    try:
        if _des3_ecb_decrypt_py(dsk, bytes.fromhex(e2)) != ts.to_bytes(8, "big"):
            return False
    except Exception:
        return False
    return True


@app.post("/api/l35")
def api_l35(page: int = Form(...), ts: int = Form(...), e1: str = Form(...),
            e2: str = Form(...), sign: str = Form(...)):
    _check_ts(ts)
    if _l35_try("Fatdog_sneak", page, ts, e1, e2, sign):
        _check_page(page, PAGES35)
        idx = (page - 1) * PER_PAGE35
        return {"page": page, "nums": NUMS35[idx:idx + PER_PAGE35]}
    for dk in DECOY35_KEYS:
        if _l35_try(dk, page, ts, e1, e2, sign):
            raise HTTPException(status_code=403, detail="sign invalid")
    return {"page": page, "nums": []}
_K34_SUBS = [hashlib.sha256(KEY34_HMAC + str(i).encode()).digest()[:4] for i in range(8)]


def _k34_f(i: int, x: bytes) -> bytes:
    return hashlib.sha256(_K34_SUBS[i] + x).digest()[:4]


def k34_feistel_dec(data: bytes) -> bytes:
    out = bytearray()
    for off in range(0, len(data) - len(data) % 8, 8):
        L, R = data[off:off + 4], data[off + 4:off + 8]
        for i in reversed(range(8)):
            L, R = bytes(x ^ y for x, y in zip(R, _k34_f(i, L))), L
        out += L + R
    return bytes(out)

# ---------------- 关卡 23：WebView 白屏（证书错误） ----------------
# 页面只接受 HTTPS；HTTP 端口访问一律 403。
# App 端 WebView 不信任自签证书 → onReceivedSslError → handler.cancel() 白屏；
# Hook onReceivedSslError 调 handler.proceed() 放行后，页面出现，App 从 #flag 取走 flag。
FLAG23 = "FLAG_18_L23{webview_ssl_error}"

PAGE23 = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>胖狗迷雾栈</title>
<style>
  body{background:#0f0f14;color:#ececf2;font-family:sans-serif;padding:24px;line-height:1.8}
  h1{color:#fb7299;font-size:20px}
  .card{background:#24242b;border-radius:12px;padding:16px;margin-top:14px}
  #flag{color:#7ee787;font-weight:bold;font-family:monospace;word-break:break-all}
  .mist{color:#9a9aa3}
</style>
</head>
<body>
<h1>迷雾栈 · 白云深处</h1>
<p class="mist">浓雾未散前，谁也看不见栈里藏了什么。证书不受信任时，页面永远停在白屏。</p>
<div class="card">
<p>栈主留言：能穿过证书迷雾看到这页，说明你已经把 WebView 的 SSL 错误处理按在了脚下。</p>
<p>通关密令：<span id="flag">""" + FLAG23 + """</span></p>
</div>
<p class="mist">ps: 这页只讲 HTTPS，用 HTTP 来敲门会吃 403。</p>
</body>
</html>"""


# ---------------- 密码学原语 ----------------

def rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for ch in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(ch ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)

_MASK = 0xFFFFFFFF

def _rl(x, n):
    n = n & 31
    return ((x << n) | (x >> (32 - n))) & _MASK

# ---- SM3（国密哈希，纯 Python，对齐 App 端 Sm3Core） ----
_IV3 = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]

def sm3(msg: bytes) -> bytes:
    bitlen = len(msg) * 8
    paddedLen = ((len(msg) + 8) // 64) * 64 + 64
    p = bytearray(paddedLen)
    p[:len(msg)] = msg
    p[len(msg)] = 0x80
    for i in range(8):
        p[paddedLen - 1 - i] = (bitlen >> (8 * i)) & 0xFF
    v = _IV3[:]
    for off in range(0, paddedLen, 64):
        w = [0] * 68
        w1 = [0] * 64
        for i in range(16):
            w[i] = int.from_bytes(bytes(p[off + i * 4: off + i * 4 + 4]), "big")
        for i in range(16, 68):
            t = (w[i - 16] ^ w[i - 9] ^ _rl(w[i - 3], 15)) & _MASK
            w[i] = (t ^ _rl(t, 15) ^ _rl(t, 23) ^ _rl(w[i - 13], 7) ^ w[i - 6]) & _MASK
        for i in range(64):
            w1[i] = w[i] ^ w[i + 4]
        a, b, c, d, e, f, g, h = v
        for j in range(64):
            tj = 0x79cc4519 if j < 16 else 0x7a879d8a
            ss1 = _rl((_rl(a, 12) + e + _rl(tj, j)) & _MASK, 7)
            ss2 = ss1 ^ _rl(a, 12)
            ff = (a ^ b ^ c) if j < 16 else ((a & b) | (a & c) | (b & c))
            gg = (e ^ f ^ g) if j < 16 else ((e & f) | (~e & g))
            tt1 = (ff + d + ss2 + w1[j]) & _MASK
            tt2 = (gg + h + ss1 + w[j]) & _MASK
            d, c, b, a = c, _rl(b, 9), a, tt1
            h, g, f, e = g, _rl(f, 19), e, (tt2 ^ _rl(tt2, 9) ^ _rl(tt2, 17)) & _MASK
        v = [(v[0] ^ a) & _MASK, (v[1] ^ b) & _MASK, (v[2] ^ c) & _MASK, (v[3] ^ d) & _MASK,
             (v[4] ^ e) & _MASK, (v[5] ^ f) & _MASK, (v[6] ^ g) & _MASK, (v[7] ^ h) & _MASK]
    out = bytearray(32)
    for i in range(8):
        out[i * 4:i * 4 + 4] = v[i].to_bytes(4, "big")
    return bytes(out)

def sm3_hex(data: bytes) -> str:
    return sm3(data).hex()

# ---- SM4（国密分组密码，纯 Python，对齐 App 端 Sm4Core） ----
_SBOX = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2,
    0x28, 0xfb, 0x2c, 0x05, 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
    0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4,
    0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa,
    0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
    0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2,
    0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b,
    0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
    0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf, 0x8a, 0xd2,
    0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30,
    0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
    0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45,
    0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41,
    0x1f, 0x10, 0x5a, 0xd8, 0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
    0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0, 0x89, 0x69, 0x97, 0x4a,
    0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e,
    0xd7, 0xcb, 0x39, 0x48]

_FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
_CK = [0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1,
       0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
       0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1,
       0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
       0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41,
       0x484f565d, 0x646b7279]

def _tau(w):
    return ((_SBOX[(w >> 24) & 0xFF] << 24) | (_SBOX[(w >> 16) & 0xFF] << 16)
            | (_SBOX[(w >> 8) & 0xFF] << 8) | _SBOX[w & 0xFF]) & _MASK

def _pl1(b):
    return (b ^ _rl(b, 2) ^ _rl(b, 10) ^ _rl(b, 18) ^ _rl(b, 24)) & _MASK

def _pl2(b):
    return (b ^ _rl(b, 13) ^ _rl(b, 23)) & _MASK

def _sm4_keys(key: bytes):
    k = [0] * 36
    for i in range(4):
        k[i] = (int.from_bytes(key[i * 4:i * 4 + 4], "big") ^ _FK[i]) & _MASK
    rk = [0] * 32
    for i in range(32):
        k[i + 4] = (k[i] ^ _pl2(_tau((k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ _CK[i]) & _MASK))) & _MASK
        rk[i] = k[i + 4]
    return rk

def _sm4_block(inp, off, out, ooff, rk):
    x = [0] * 36
    for i in range(4):
        x[i] = int.from_bytes(inp[off + i * 4: off + i * 4 + 4], "big")
    for i in range(32):
        x[i + 4] = (x[i] ^ _pl1(_tau((x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]) & 0xFFFFFFFF))) & _MASK
    for i in range(4):
        val = x[35 - i]
        out[ooff + i * 4: ooff + i * 4 + 4] = val.to_bytes(4, "big")

def sm4_encrypt(data: bytes, key: bytes) -> bytes:
    rk = _sm4_keys(key)
    padlen = 16 - len(data) % 16
    padded = data + bytes([padlen] * padlen)
    out = bytearray(len(padded))
    for i in range(0, len(padded), 16):
        _sm4_block(padded, i, out, i, rk)
    return bytes(out)

def sm4_decrypt(data: bytes, key: bytes) -> bytes:
    rk = _sm4_keys(key)
    rkrev = rk[::-1]
    out = bytearray(len(data))
    for i in range(0, len(data), 16):
        _sm4_block(data, i, out, i, rkrev)
    pad = out[-1]
    return bytes(out[:-pad])

_RSA_KEY = None
if HAVE_CRYPTO:
    _RSA_KEY = _RSA.construct((KEY18_RSA_N, KEY18_RSA_E, KEY18_RSA_D))

def aes_enc(key, data): return _AES.new(key, _AES.MODE_ECB).encrypt(pad(data, 16))

def aes_dec(key, data): return unpad(_AES.new(key, _AES.MODE_ECB).decrypt(data), 16)

def des_enc(key, data): return _DES.new(key, _DES.MODE_ECB).encrypt(pad(data, 8))

def rsa_priv_decrypt(ct):
    out = PKCS1_v1_5.new(_RSA_KEY).decrypt(ct, None)
    if out is None:
        raise ValueError("bad padding")
    return out

def _check_page(page, pages):
    if not (1 <= page <= pages):
        raise HTTPException(status_code=400, detail="page out of range")

def _check_ts(ts):
    if abs(int(time.time()) - ts) > TS_WINDOW:
        raise HTTPException(status_code=403, detail="timestamp expired")

@app.get("/api/page")
def api_page(page: int = Query(...), ts: int = Query(...), sign: str = Query(...)):
    _check_page(page, PAGES)
    _check_ts(ts)
    if not hmac.compare_digest(sign, hmac.new(KEY, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()):
        raise HTTPException(status_code=403, detail="sign invalid")
    idx = (page - 1) * PER_PAGE
    return {"page": page, "nums": NUMS[idx:idx + PER_PAGE]}

@app.get("/api/rc4")
def api_rc4(payload: str = Query(...), sig: str = Query(...)):
    if not hmac.compare_digest(sig, hashlib.md5((payload + SIG16_SALT.decode()).encode()).hexdigest()):
        raise HTTPException(status_code=403, detail="sig invalid")
    try:
        raw = bytes.fromhex(payload)
    except ValueError:
        raise HTTPException(status_code=400, detail="payload not hex")
    try:
        plain = rc4(KEY16_REQ, raw).decode()
    except Exception:
        raise HTTPException(status_code=403, detail="payload decrypt failed")
    m = re.fullmatch(r"page=(\d+)&ts=(\d+)", plain)
    if not m:
        raise HTTPException(status_code=403, detail="payload format invalid")
    page, ts = int(m.group(1)), int(m.group(2))
    _check_page(page, PAGES16)
    _check_ts(ts)
    idx = (page - 1) * PER_PAGE16
    body = f"page={page}|nums={','.join(str(n) for n in NUMS16[idx:idx + PER_PAGE16])}"
    return {"d": rc4(KEY16_RSP, body.encode()).hex()}

@app.post("/api/form")
def api_form(page: int = Form(...), ts: int = Form(...), dog: str = Form(...),
            enc: str = Form(...), sig: str = Form(...), client: str = Form(""), chan: str = Form(""),
            ver: str = Form(""), dev: str = Form("")):
    if dog != DOG17:
        raise HTTPException(status_code=403, detail="dog invalid")
    _check_ts(ts)
    if not hmac.compare_digest(sig, sm3_hex((enc + SIG17_SALT.decode()).encode())):
        raise HTTPException(status_code=403, detail="sig invalid")
    try:
        plain = sm4_decrypt(bytes.fromhex(enc), KEY17_REQ).decode()
    except Exception:
        raise HTTPException(status_code=403, detail="enc decrypt failed")
    m = re.fullmatch(r"page=(\d+)&ts=(\d+)", plain)
    if not m or int(m.group(1)) != page or int(m.group(2)) != ts:
        raise HTTPException(status_code=403, detail="enc/param mismatch")
    _check_page(page, PAGES17)
    idx = (page - 1) * PER_PAGE17
    body = f"page={page}|nums={','.join(str(n) for n in NUMS17[idx:idx + PER_PAGE17])}"
    return {"d": sm4_encrypt(body.encode(), KEY17_RSP).hex()}

@app.get("/api/dskey")
def api_dskey():
    return {"k": DES18_HALF_A_HEX}

@app.post("/api/rsa")
def api_rsa(page: int = Form(...), ts: int = Form(...), enc: str = Form(...),
           client: str = Form(""), chan: str = Form(""), ver: str = Form(""), dev: str = Form("")):
    if not HAVE_CRYPTO:
        raise HTTPException(status_code=500, detail="服务端缺 pycryptodome，请 pip install pycryptodome")
    _check_ts(ts)
    try:
        plain = rsa_priv_decrypt(bytes.fromhex(enc)).decode()
    except Exception:
        raise HTTPException(status_code=403, detail="enc decrypt failed")
    m = re.fullmatch(r"page=(\d+)&ts=(\d+)", plain)
    if not m or int(m.group(1)) != page or int(m.group(2)) != ts:
        raise HTTPException(status_code=403, detail="enc/param mismatch")
    _check_page(page, PAGES18)
    idx = (page - 1) * PER_PAGE18
    body = f"page={page}|nums={','.join(str(n) for n in NUMS18[idx:idx + PER_PAGE18])}"
    return {"d": des_enc(KEY18_DES, body.encode()).hex()}

@app.post("/api/l19")
def api_l19(page: int = Form(...), ts: int = Form(...), enc: str = Form(...), sign: str = Form(...),
           client: str = Form(""), chan: str = Form(""), ver: str = Form(""), dev: str = Form("")):
    if not HAVE_CRYPTO:
        raise HTTPException(status_code=500, detail="服务端缺 pycryptodome，请 pip install pycryptodome")
    _check_ts(ts)
    if not hmac.compare_digest(sign, hmac.new(KEY19_HMAC, enc.encode(), hashlib.sha256).hexdigest()):
        raise HTTPException(status_code=403, detail="sign invalid")
    try:
        plain = aes_dec(KEY19_AES_REQ, bytes.fromhex(enc)).decode()
    except Exception:
        raise HTTPException(status_code=403, detail="enc decrypt failed")
    m = re.fullmatch(r"page=(\d+)&ts=(\d+)", plain)
    if not m or int(m.group(1)) != page or int(m.group(2)) != ts:
        raise HTTPException(status_code=403, detail="enc/param mismatch")
    _check_page(page, PAGES19)
    idx = (page - 1) * PER_PAGE19
    body = f"page={page}|nums={','.join(str(n) for n in NUMS19[idx:idx + PER_PAGE19])}"
    return {"d": aes_enc(KEY19_AES_RSP, body.encode()).hex()}

@app.get("/api/tls")
def api_tls(page: int = Query(...), ts: int = Query(...), sign: str = Query(...)):
    _check_page(page, PAGES21)
    _check_ts(ts)
    if not hmac.compare_digest(sign, hmac.new(KEY21_HMAC, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()):
        raise HTTPException(status_code=403, detail="sign invalid")
    idx = (page - 1) * PER_PAGE21
    return {"page": page, "nums": NUMS21[idx:idx + PER_PAGE21]}

@app.get("/api/pin")
def api_pin(page: int = Query(...), ts: int = Query(...), sign: str = Query(...)):
    _check_page(page, PAGES22)
    _check_ts(ts)
    if not hmac.compare_digest(sign, hmac.new(KEY22_HMAC, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()):
        raise HTTPException(status_code=403, detail="sign invalid")
    idx = (page - 1) * PER_PAGE22
    return {"page": page, "nums": NUMS22[idx:idx + PER_PAGE22]}


@app.get("/api/swap")
def api_swap(page: int = Query(...), ts: int = Query(...), sign: str = Query(...)):
    _check_page(page, PAGES24)
    _check_ts(ts)
    if not hmac.compare_digest(sign, hmac.new(KEY24_HMAC, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()):
        raise HTTPException(status_code=403, detail="sign invalid")
    idx = (page - 1) * PER_PAGE24
    return {"page": page, "nums": NUMS24[idx:idx + PER_PAGE24]}


@app.get("/api/native")
def api_native(page: int = Query(...), ts: int = Query(...), sign: str = Query(...)):
    _check_page(page, PAGES25)
    _check_ts(ts)
    if not hmac.compare_digest(sign, hmac.new(KEY25_HMAC, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()):
        raise HTTPException(status_code=403, detail="sign invalid")
    idx = (page - 1) * PER_PAGE25
    return {"page": page, "nums": NUMS25[idx:idx + PER_PAGE25]}


@app.get("/api/l28")
def api_l28(page: int = Query(...), ts: int = Query(...), sign: str = Query(...)):
    _check_page(page, PAGES28)
    _check_ts(ts)
    if not hmac.compare_digest(sign, hmac.new(KEY28_HMAC, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()):
        raise HTTPException(status_code=403, detail="sign invalid")
    idx = (page - 1) * PER_PAGE28
    return {"page": page, "nums": NUMS28[idx:idx + PER_PAGE28]}


@app.get("/api/l29")
def api_l29(page: int = Query(...), ts: int = Query(...), sign: str = Query(...)):
    _check_page(page, PAGES29)
    _check_ts(ts)
    if not hmac.compare_digest(sign, hmac.new(KEY29_HMAC, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()):
        raise HTTPException(status_code=403, detail="sign invalid")
    idx = (page - 1) * PER_PAGE29
    return {"page": page, "nums": NUMS29[idx:idx + PER_PAGE29]}


@app.get("/api/l30")
def api_l30(page: int = Query(...), ts: int = Query(...), sign: str = Query(...)):
    _check_page(page, PAGES30)
    _check_ts(ts)
    if not hmac.compare_digest(sign, hmac.new(KEY30_HMAC, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()):
        raise HTTPException(status_code=403, detail="sign invalid")
    idx = (page - 1) * PER_PAGE30
    return {"page": page, "nums": NUMS30[idx:idx + PER_PAGE30]}

def _l31_try(k, page, ts, enc, sign):
    """用候选密钥 k 完整验证一包：HMAC 对 + RC4 解密出的载荷与表单一致"""
    if not hmac.compare_digest(sign, hmac.new(k, enc.encode(), hashlib.sha256).hexdigest()):
        return False
    try:
        plain = rc4(k, bytes.fromhex(enc)).decode("utf-8", "ignore")
    except Exception:
        return False
    m = re.fullmatch(r"page=(\d+)&ts=(\d+)", plain or "")
    return bool(m) and int(m.group(1)) == page and int(m.group(2)) == ts


@app.post("/api/l31")
def api_l31(page: int = Form(...), ts: int = Form(...), enc: str = Form(...), sign: str = Form(...)):
    _check_ts(ts)
    if _l31_try(KEY31_HMAC, page, ts, enc, sign):
        _check_page(page, PAGES31)
        idx = (page - 1) * PER_PAGE31
        return {"page": page, "nums": NUMS31[idx:idx + PER_PAGE31]}
    for dk in DECOY31_KEYS:
        if _l31_try(dk, page, ts, enc, sign):
            raise HTTPException(status_code=403, detail="sign invalid")
    # 其余一律"形似而空"：200 但没有数字——逼玩家靠内容分辨真假包
    return {"page": page, "nums": []}

@app.get("/api/l32")
def api_l32(page: int = Query(...), ts: int = Query(...), sign: str = Query(...)):
    _check_page(page, PAGES32)
    _check_ts(ts)
    if not hmac.compare_digest(sign, hmac.new(KEY32_HMAC, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()):
        raise HTTPException(status_code=403, detail="sign invalid")
    idx = (page - 1) * PER_PAGE32
    return {"page": page, "nums": NUMS32[idx:idx + PER_PAGE32]}

@app.get("/api/l33")
def api_l33(page: int = Query(...), ts: int = Query(...), sign: str = Query(...)):
    _check_page(page, PAGES33)
    _check_ts(ts)
    if not hmac.compare_digest(sign, hmac.new(KEY33_HMAC, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()):
        raise HTTPException(status_code=403, detail="sign invalid")
    idx = (page - 1) * PER_PAGE33
    return {"page": page, "nums": NUMS33[idx:idx + PER_PAGE33]}

@app.post("/api/l34")
def api_l34(page: int = Form(...), ts: int = Form(...), enc: str = Form(...), sign: str = Form(...),
            dev: str = Form("x"), ver: str = Form("1")):
    _check_ts(ts)
    if not hmac.compare_digest(sign, hmac.new(KEY34_HMAC, enc.encode(), hashlib.sha256).hexdigest()):
        raise HTTPException(status_code=403, detail="sign invalid")
    try:
        raw = k34_feistel_dec(bytes.fromhex(enc))
    except Exception:
        raise HTTPException(status_code=403, detail="enc invalid")
    plain = raw.split(b"\x00")[0].decode("utf-8", "ignore")
    m = re.fullmatch(r"page=(\d+)&ts=(\d+)", plain or "")
    if not m or int(m.group(1)) != page or int(m.group(2)) != ts:
        raise HTTPException(status_code=403, detail="param mismatch")
    _check_page(page, PAGES34)
    idx = (page - 1) * PER_PAGE34
    body = f"page={page}|nums={','.join(str(n) for n in NUMS34[idx:idx + PER_PAGE34])}"
    return {"d": rc4(RSP34_KEY, body.encode()).hex()}


@app.get("/h5/v23", response_class=HTMLResponse)
def h5_v23(request: Request):
    # 只接受 HTTPS；App 端 WebView 不信任自签证书 → onReceivedSslError → 白屏。
    # 绕过：Hook onReceivedSslError 调 handler.proceed() 放行（或 curl -k 直接看页面）。
    if request.scope.get("scheme") != "https":
        raise HTTPException(status_code=403, detail="this page only speaks https")
    return PAGE23


# ---------------- 关卡 26：mTLS 独立实例 ----------------
# 注意：/api/mtls 只挂在 :8444 的独立 app 上——主 app（8787/8443）里根本没有这个路由，
# 玩家没法不带客户端证书从 8443/8787 拿到数据。8444 由 uvicorn 在握手层强制验证客户端证书
# （ssl_cert_reqs=CERT_REQUIRED，信任 certs/ca.crt 签发的客户端证书，见 gen_certs.py）。
mtls_app = FastAPI(title="FatdogReverse mTLS", docs_url=None, redoc_url=None, openapi_url=None)


@mtls_app.get("/api/mtls")
def api_mtls(page: int = Query(...), ts: int = Query(...), sign: str = Query(...)):
    _check_page(page, PAGES26)
    _check_ts(ts)
    if not hmac.compare_digest(sign, hmac.new(KEY26_HMAC, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()):
        raise HTTPException(status_code=403, detail="sign invalid")
    idx = (page - 1) * PER_PAGE26
    return {"page": page, "nums": NUMS26[idx:idx + PER_PAGE26]}


# ---------------- 关卡 27：万法归宗 ----------------
# 复合签名复用 L19 那套：enc = hex(AES(req_key, "page=N&ts=T"))，sign = HMAC(hmac_key, enc)，
# 响应体 {"d": hex} 用另一把 AES 密钥加密。App 侧走 HTTPS:8443（TrustManager + CertificatePinner 双闸门）。
@app.post("/api/l27")
def api_l27(page: int = Form(...), ts: int = Form(...), enc: str = Form(...), sign: str = Form(...),
           client: str = Form(""), chan: str = Form(""), ver: str = Form(""), dev: str = Form("")):
    if not HAVE_CRYPTO:
        raise HTTPException(status_code=500, detail="服务端缺 pycryptodome，请 pip install pycryptodome")
    _check_ts(ts)
    if not hmac.compare_digest(sign, hmac.new(KEY27_HMAC, enc.encode(), hashlib.sha256).hexdigest()):
        raise HTTPException(status_code=403, detail="sign invalid")
    try:
        plain = aes_dec(KEY27_AES_REQ, bytes.fromhex(enc)).decode()
    except Exception:
        raise HTTPException(status_code=403, detail="enc decrypt failed")
    m = re.fullmatch(r"page=(\d+)&ts=(\d+)", plain)
    if not m or int(m.group(1)) != page or int(m.group(2)) != ts:
        raise HTTPException(status_code=403, detail="enc/param mismatch")
    _check_page(page, PAGES27)
    idx = (page - 1) * PER_PAGE27
    body = f"page={page}|nums={','.join(str(n) for n in NUMS27[idx:idx + PER_PAGE27])}"
    return {"d": aes_enc(KEY27_AES_RSP, body.encode()).hex()}

if __name__ == "__main__":
    cert_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
    print(f"FatdogReverse 服务端（FastAPI）：http://{HOST}:{PORT_HTTP}（15-20） https://{HOST}:{PORT_HTTPS}（21-27）")
    print(f"L23 页面: https://{HOST}:{PORT_HTTPS}/h5/v23 （只讲 HTTPS，HTTP 端口访问 403）")
    print(f"L26 mTLS: https://{HOST}:8444/api/mtls （双向 TLS：必须出示 certs/client.p12 里的客户端证书）")
    print(f"数字加和：L15={sum(NUMS)} L16={sum(NUMS16)} L17={sum(NUMS17)} L18={sum(NUMS18)} L19={sum(NUMS19)} "
          f"L21={sum(NUMS21)} L22={sum(NUMS22)} L24={sum(NUMS24)} L25={sum(NUMS25)} L26={sum(NUMS26)} L27={sum(NUMS27)} "
          f"L28={sum(NUMS28)} L29={sum(NUMS29)} L30={sum(NUMS30)} L31={sum(NUMS31)} L32={sum(NUMS32)} L33={sum(NUMS33)} L34={sum(NUMS34)} L35={sum(NUMS35)} L36={sum(NUMS36)} L37={sum(NUMS37)} "
          f"KL6={sum(NUMS43)} KL7={sum(NUMS44)}")
    http_cfg = uvicorn.Config(app, host=HOST, port=PORT_HTTP, log_level="info")
    threading.Thread(target=uvicorn.Server(http_cfg).run, daemon=True).start()
    https_cfg = uvicorn.Config(app, host=HOST, port=PORT_HTTPS,
                               ssl_keyfile=os.path.join(cert_dir, "server.key"),
                               ssl_certfile=os.path.join(cert_dir, "server.crt"), log_level="info")
    threading.Thread(target=uvicorn.Server(https_cfg).run, daemon=True).start()
    mtls_cfg = uvicorn.Config(mtls_app, host=HOST, port=8444,
                              ssl_keyfile=os.path.join(cert_dir, "server.key"),
                              ssl_certfile=os.path.join(cert_dir, "server.crt"),
                              ssl_cert_reqs=2,   # ssl.CERT_REQUIRED：握手层强制客户端证书
                              ssl_ca_certs=os.path.join(cert_dir, "ca.crt"), log_level="info")
    uvicorn.Server(mtls_cfg).run()