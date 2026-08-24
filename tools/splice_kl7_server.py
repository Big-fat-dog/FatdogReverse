# -*- coding: utf-8 -*-
"""一次性脚本：把 /api/kl7 路由段（含魔改 DES 镜像）拼进 server.py。
表格全部从 gen_kl7 导入，杜绝转录误差。"""
import io
import re
import sys

sys.path.insert(0, ".")
import gen_kl7 as g


def fmt(name, vals, per=16):
    lines = [name + " = ["]
    for i in range(0, len(vals), per):
        lines.append("    " + ", ".join(str(v) for v in vals[i:i + per]) + ",")
    lines.append("]")
    return "\n".join(lines)


def fmt_sboxes():
    out = ["_S44 = ["]
    for box in g.SBOXES_MOD:
        out.append("    [")
        for r in range(4):
            row = box[r * 16:(r + 1) * 16]
            out.append("        " + ", ".join(str(v) for v in row) + ",")
        out.append("    ],")
    out.append("]")
    return "\n".join(out)


section = []
A = section.append
A("")
A("# ---------------- 关卡 44（KL7）裂魂之匣：魔改 DES（IP 首尾互换 + S3 换位 + FP 重算） ----------------")
A("KEY44_MASTER = \"Fatdog_shatter\"")
A("DECOY44_KEYS = [\"Fatdog_scatter\"]")
A("PAGES44, PER_PAGE44, SEED44 = 100, 10, 20271115")
A("_rng44 = random.Random(SEED44)")
A("NUMS44 = [_rng44.randint(1, 100) for _ in range(PAGES44 * PER_PAGE44)]")
A("")
A(fmt("_IP44", g.IP_MOD))       # IP[0]<->IP[63] 首尾互换
A(fmt("_FP44", g.FP_MOD))       # FP 为魔改 IP 的逆置换
A(fmt("_E44", g.E_TAB))
A(fmt("_PC144", g.PC1))
A(fmt("_PC244", g.PC2))
A(fmt("_SHIFTS44", g.SHIFTS, per=16))
A(fmt("_P44", g.P_TAB))
A(fmt_sboxes())                 # S3 扁平下标 18/19 两值互换（9<->0）
A("""
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
    \"\"\"魔改 3DES-EDE 解密 p = D(K1, E(K2, D(K3, c)))，与 libm2.so 手写实现互为镜像\"\"\"
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
        plain = p.split(b"\\x00")[0].decode("utf-8", "ignore")
    except Exception:
        return False
    m = re.fullmatch(r"page=(\\d+)&ts=(\\d+)", plain or "")
    return bool(m) and int(m.group(1)) == page and int(m.group(2)) == ts


@app.post("/api/kl7")
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
""")

new_text = "\n".join(section)

with io.open("server.py", "r", encoding="utf-8") as f:
    src = f.read()

anchor = "_des3_ecb_encrypt_py(key24"
idx = src.find("def " + anchor)
assert idx > 0, "anchor not found"

# 幂等：已拼过就先移除旧段
start_marker = "# ---------------- 关卡 44（KL7）裂魂之匣"
s0 = src.find(start_marker)
if s0 >= 0 and s0 < idx:
    src = src[:s0] + src[idx:]
    idx = src.find("def " + anchor)

src = src[:idx] + new_text.strip("\n") + "\n\n\n" + src[idx:]
src = src.replace('f"KL6={sum(NUMS43)}")', 'f"KL6={sum(NUMS43)} KL7={sum(NUMS44)}")')

with io.open("server.py", "w", encoding="utf-8", newline="\n") as f:
    f.write(src)

print("[splice] ok, /api/kl7 section inserted before _des3_ecb_encrypt_py")
print("[check] NUMS44 sum =", sum(g.__dict__.get('x', 0) for x in []) or "see server import")
