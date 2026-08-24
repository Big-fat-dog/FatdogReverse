# -*- coding: utf-8 -*-
"""KL7 端到端验证：真起 server.py，Python 复刻取数 100 页 + 诱饵/错签负例"""
import hashlib
import hmac
import json
import ssl
import sys
import time
import urllib.request
import urllib.parse

sys.path.insert(0, ".")
import gen_kl7 as g

MK = b"Fatdog_shatter"
DK = hashlib.sha256(MK + b"|des").digest()[:24]
MACK = hashlib.sha256(MK + b"|mac").digest()
BASE = "https://127.0.0.1:8443/api/kl7"

ctx = ssl.create_default_context(cafile="certs/ca.crt")
ctx.check_hostname = False


def post(page, ts, enc_hex, sign):
    data = urllib.parse.urlencode({"page": page, "ts": ts,
                                   "enc": enc_hex, "sign": sign}).encode()
    req = urllib.request.Request(BASE, data=data)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, None


def make(page):
    ts = int(time.time())
    enc = g.ede_encrypt(DK, g.pad8(f"page={page}&ts={ts}".encode())).hex()
    sign = hmac.new(MACK, enc.encode(), hashlib.sha256).hexdigest()
    return ts, enc, sign


# 等服务就绪
for i in range(40):
    try:
        post(1, int(time.time()), "00", "x")
        break
    except Exception:
        time.sleep(0.5)

total, bad = 0, 0
for p in range(1, 101):
    ts, enc, sign = make(p)
    code, obj = post(p, ts, enc, sign)
    assert code == 200 and obj and len(obj["nums"]) == 10, (p, code, obj)
    total += sum(obj["nums"])
print("[e2e] 100 pages ok, sum =", total)

# 负例 1：近亲假钥 Fatdog_scatter 完整构造 -> 403
ts = int(time.time())
enc = g.ede_encrypt(hashlib.sha256(b"Fatdog_scatter|des").digest()[:24],
                    g.pad8(f"page=1&ts={ts}".encode())).hex()
sign = hmac.new(hashlib.sha256(b"Fatdog_scatter|mac").digest(),
                enc.encode(), hashlib.sha256).hexdigest()
code, _ = post(1, ts, enc, sign)
print("[e2e] decoy Fatdog_scatter ->", code, "(want 403)")

# 负例 2：错签 -> nums []
ts, enc, _ = make(1)
bad_sign = "0" * 64
code, obj = post(1, ts, enc, bad_sign)
print("[e2e] wrong sign ->", code, "nums =", obj["nums"], "(want [])")

# 负例 3：标准 DES（未魔改）构造 -> 解不开 -> nums []
try:
    from Crypto.Cipher import DES3
    ts = int(time.time())
    payload = f"page=1&ts={ts}".encode()
    payload += b"\x00" * ((-len(payload)) % 8)
    ct = DES3.new(DK, DES3.MODE_ECB).encrypt(payload)   # 标准 3DES
    enc = ct.hex()
except ImportError:
    enc = make(1)[1]
sign = hmac.new(MACK, enc.encode(), hashlib.sha256).hexdigest()
code, obj = post(1, ts, enc, sign)
print("[e2e] std-3DES enc ->", code, "nums =", obj["nums"], "(want [] = 标准库解不开魔改密文的反证)")

print("[expect] sum should be 48865:", total == 48865)
