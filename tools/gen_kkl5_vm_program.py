# -*- coding: utf-8 -*-
r"""KKL5 诛仙台：VMP 字节码生成器（内存机 · 累加器 · 差分反馈链）。

把"从真标记 + salt 派生 32 字节主钥（16B SM4 密钥 + 16B AES 密钥）"的门禁逻辑
编译成一台自造**内存机**（16 个内存单元 M0..M15 + 一个累加器 acc）的字节码，
再用**差分反馈链**加密，写进 app/jni/kkl5_vm_program.h。

与 KKL3 / KKL4 的 VM 刻意**三机不同构**（同一款靶场里三个 VM 不能长得一样）：

| 维度   | KKL5（本文件）                       | KKL3                     | KKL4                          |
|--------|--------------------------------------|--------------------------|-------------------------------|
| 架构   | **内存机**：16 单元 M[]+累加器 acc   | 16 通用寄存器机          | 数据栈 + 4 寄存器 + CALL/RET  |
| 编码   | `(op<<24)\|(d<<20)\|(s<<16)\|imm16`  | `(imm16<<16)\|(rd<<12)\|(rs<<8)\|op` | `(op<<28)\|imm28` |
| 解密   | **差分反馈链**：d_n=e_n^K[n%L]^e_{n-1}（密文自反馈） | 周期滚动异或（可整段解） | 链式密钥演进（key 递推） |
| 控制流 | 绝对跳转，无子程序、无数据栈         | 绝对跳转                 | CALL/RET 子程序（独立返回栈） |
| 派生式 | `ror8(x,3)` + 0x2D/0x3B/0x53 + `si>>1` + `mi*3` | `ror8` + 0x3D/0x29/0x1B | `rol8(x,3)` + 0x51/0x37/0x23 |
| 输出   | 32 字节（SM4 key + AES key）         | 16 字节                  | 32 字节                       |

真标记 `Fatdog_ascend` **不以任何形式**出现在字节码里：程序只有 `GETM idx`
（取数下标是编译期常量 `i%13` / `13+i%11`），标记字节由门面在运行时从 .data 的
UTF-16 数组喂入。明文诱饵 `Fatdog_ascent`（仅末位一字之差）躺 .rodata，用它拼出的
输入派生出的主钥服务端不认（403）。

★ 旧版两处缺陷在本文件中被根除：
  ① 跳转：全部改用**绝对**目标（`pc = imm16`），不再有 `target-pc` 相对约定 → 无偏移差 1；
  ② 32 位立即数：`SET d,lo` + `SETH d,hi` 成对（解释器逐语义一致），并用往返自测锁定。

自测（默认开）：生成器内嵌一个与 vellum.cpp 逐语义对齐的 Python 解释器，
跑真程序必须 HALT 且 32B 输出 == 纯函数派生值；换诱饵输入派生值必须不同；
外加 SET/SETH 32 位往返用例（守护缺陷②）。
"""
import struct
import sys

# ─────────────── 指令集：op 占最高字节；d/s 各 4 位；imm 低 16 位 ───────────────
OP_SET  = 0x01  # M[d] = imm16
OP_SETH = 0x02  # M[d] = (M[d] & 0x0000FFFF) | (imm16 << 16)
OP_CPY  = 0x03  # M[d] = M[s]
OP_GETA = 0x04  # acc = M[d]
OP_PUTA = 0x05  # M[d] = acc
OP_GETM = 0x06  # acc = in[imm8]
OP_ADDI = 0x07  # acc = (acc + imm16) & 0xFFFFFFFF
OP_MULK = 0x08  # acc = (acc * imm16) & 0xFFFFFFFF
OP_XORR = 0x09  # acc ^= M[s]
OP_ANDR = 0x0A  # acc &= M[s]
OP_ORR  = 0x0B  # acc |= M[s]
OP_ADDR = 0x0C  # acc = (acc + M[s]) & 0xFFFFFFFF
OP_SUBR = 0x0D  # acc = (acc - M[s]) & 0xFFFFFFFF
OP_SHL  = 0x0E  # acc = (acc << (imm & 0x1F)) & 0xFFFFFFFF
OP_SHR  = 0x0F  # acc = acc >> (imm & 0x1F)
OP_ROL8 = 0x10  # acc = rol8(acc & 0xFF, imm & 7)
OP_ROR8 = 0x11  # acc = ror8(acc & 0xFF, imm & 7)
OP_XORI = 0x12  # acc ^= imm16
OP_ANDI = 0x13  # acc &= imm16
OP_JMP  = 0x14  # pc = imm16     （绝对）
OP_JZ   = 0x15  # if acc == 0: pc = imm16
OP_JNZ  = 0x16  # if acc != 0: pc = imm16
OP_HALT = 0x17

MARKER_REAL = b"Fatdog_ascend"      # 13 字节（真）
MARKER_DECOY = b"Fatdog_ascent"     # 13 字节（诱饵，仅末位 d/t 一字之差）
SALT_KEY = b"|kkl5_altar"           # 11 字节
NB = 32                             # 派生字节数：16B SM4 key + 16B AES key
STREAM_KEY = bytes(range(0x21, 0x31))   # 16 字节差分链密钥流
CHAIN_IV = 0x9E3779B9               # 差分链初值

M32 = 0xFFFFFFFF
OUT_WORDS = NB // 4                 # 8 个输出单元
OUT_BASE = 8                        # M8..M15 存输出


def enc(op, d=0, s=0, imm=0):
    return ((op & 0xFF) << 24) | ((d & 0xF) << 20) | ((s & 0xF) << 16) | (imm & 0xFFFF)


def mov32(d, value):
    """SET 低 16 位 + SETH 高 16 位（与解释器逐语义对齐）——根除旧版半字缺陷。"""
    return [enc(OP_SET, d=d, imm=value & 0xFFFF),
            enc(OP_SETH, d=d, imm=(value >> 16) & 0xFFFF)]


# ───────────────────── 服务端同款纯函数派生 ─────────────────────
def mix_byte(marker, salt, i):
    mi = marker[i % len(marker)]
    si = salt[i % len(salt)]
    x = (mi * 0x2D + si * 0x3B + i * 0x53) & 0xFF
    x ^= (si >> 1) & 0xFF
    x = ((x >> 3) | (x << 5)) & 0xFF            # ror8 3
    return (x ^ ((mi * 3 + i) & 0xFF)) & 0xFF


def derive_key(marker, salt, n=NB):
    return bytes(mix_byte(marker, salt, i) for i in range(n))


def build_input(marker, salt):
    """运行时输入缓冲布局：marker 字节 ‖ salt 字节。"""
    return bytes(marker) + bytes(salt)


# ───────────────────────── 字节码构造 ─────────────────────────
def _round(i, mi_idx, si_idx):
    """一轮：把 mix_byte(i) 算进 acc，再拼进输出单元 M8+w 的第 p 字节。"""
    p = []
    # M1 = mi = in[mi_idx]
    p += [enc(OP_GETM, imm=mi_idx), enc(OP_PUTA, d=1)]
    # M2 = si = in[si_idx]
    p += [enc(OP_GETM, imm=si_idx), enc(OP_PUTA, d=2)]
    # M3 = i
    p += [enc(OP_SET, d=3, imm=i & 0xFFFF)]
    # x = (mi*0x2D + si*0x3B + i*0x53)
    p += [enc(OP_GETA, d=1), enc(OP_MULK, imm=0x2D), enc(OP_PUTA, d=6)]
    p += [enc(OP_GETA, d=2), enc(OP_MULK, imm=0x3B), enc(OP_ADDR, s=6), enc(OP_PUTA, d=6)]
    p += [enc(OP_GETA, d=3), enc(OP_MULK, imm=0x53), enc(OP_ADDR, s=6), enc(OP_PUTA, d=6)]
    # x &= 0xFF  (M0 恒为 0xFF)
    p += [enc(OP_GETA, d=6), enc(OP_ANDR, s=0), enc(OP_PUTA, d=6)]
    # x ^= si>>1
    p += [enc(OP_GETA, d=2), enc(OP_SHR, imm=1), enc(OP_ANDR, s=0), enc(OP_PUTA, d=7)]
    p += [enc(OP_GETA, d=6), enc(OP_XORR, s=7), enc(OP_PUTA, d=6)]
    # x = ror8(x, 3)
    p += [enc(OP_GETA, d=6), enc(OP_ROR8, imm=3), enc(OP_PUTA, d=6)]
    # t = (mi*3 + i) & 0xFF
    p += [enc(OP_GETA, d=1), enc(OP_MULK, imm=3), enc(OP_ADDR, s=3),
          enc(OP_ANDR, s=0), enc(OP_PUTA, d=7)]
    # x ^= t
    p += [enc(OP_GETA, d=6), enc(OP_XORR, s=7), enc(OP_PUTA, d=6)]
    # acc = v = x & 0xFF
    p += [enc(OP_GETA, d=6), enc(OP_ANDR, s=0)]
    # ── 拼进输出单元 M8+w 的第 p 字节 ──
    w, sh = i // 4, (i % 4) * 8
    mask_inv = (~(0xFF << sh)) & M32
    p += [enc(OP_PUTA, d=7)]                                # M7 = v
    p += mov32(4, mask_inv)                                 # M4 = ~(0xFF<<sh)
    p += [enc(OP_GETA, d=OUT_BASE + w), enc(OP_ANDR, s=4), enc(OP_PUTA, d=6)]
    p += [enc(OP_GETA, d=7), enc(OP_SHL, imm=sh), enc(OP_ORR, s=6), enc(OP_PUTA, d=OUT_BASE + w)]
    return p


def _junk(v):
    """无害垃圾：SET M6,v; GETA M6（净零副作用，只污染 M6/acc）。"""
    return [enc(OP_SET, d=6, imm=v & 0xFFFF), enc(OP_GETA, d=6)]


def build_program(marker_len, salt_len, nbytes=NB):
    """
    程序布局：
        [prologue]  SET M0,0xFF; SET M9,7; GETA M9; JZ dead   （恒不跳，制造分支错觉）
        [out-init]  M8..M15 = 0
        [rounds]    32 轮，每轮就地算一个字节写进输出单元
        [loop]      3 次有界计数循环（练 JMP/JNZ）
        [HALT]
        [dead]      死块：垃圾 + HALT（不可达）
        [decoy]     诱饵例程（不可达）
    """
    prog = []
    prog += [enc(OP_SET, d=0, imm=0xFF), enc(OP_SET, d=9, imm=7), enc(OP_GETA, d=9)]
    jz_dead = len(prog)
    prog.append(enc(OP_JZ, imm=0))                       # 稍后回填 -> dead

    for w in range(OUT_WORDS):
        prog += mov32(OUT_BASE + w, 0)

    for i in range(nbytes):
        prog += _round(i, i % marker_len, marker_len + (i % salt_len))
        if i % 7 == 6:
            prog += _junk(0x11 * (i + 1))

    # 有界计数循环：M5 = 0；循环里 M5++ 直到 M5==3
    prog.append(enc(OP_SET, d=5, imm=0))
    loop_pos = len(prog)
    prog += [enc(OP_GETA, d=5), enc(OP_ADDI, imm=1), enc(OP_PUTA, d=5),
             enc(OP_GETA, d=5), enc(OP_XORI, imm=3), enc(OP_JNZ, imm=loop_pos)]

    prog.append(enc(OP_HALT))

    dead_addr = len(prog)
    prog += _junk(0x5A5A) + [enc(OP_ADDI, imm=0xC3), enc(OP_PUTA, d=7), enc(OP_HALT)]

    # 诱饵例程：另一条"看似有料"的派生路（不可达）
    decoy_addr = len(prog)
    prog += [enc(OP_GETM, imm=0), enc(OP_XORI, imm=0x6D), enc(OP_ROL8, imm=2),
             enc(OP_PUTA, d=6), enc(OP_GETA, d=6), enc(OP_MULK, imm=0x9D),
             enc(OP_PUTA, d=7), enc(OP_HALT)]

    prog[jz_dead] = enc(OP_JZ, imm=dead_addr)
    return prog


# ── 差分反馈链：enc_n = dec_n ^ K[n%L] ^ enc_{n-1}（enc_{-1} = IV） ──
def chain_encode(words, stream_key=STREAM_KEY, iv=CHAIN_IV):
    enc_words = []
    prev = iv & M32
    for n, d in enumerate(words):
        d &= M32
        e = d ^ stream_key[n % len(stream_key)] ^ prev
        e &= M32
        enc_words.append(e)
        prev = e
    return enc_words


def chain_decode(enc_words, stream_key=STREAM_KEY, iv=CHAIN_IV):
    words = []
    prev = iv & M32
    for n, e in enumerate(enc_words):
        e &= M32
        d = e ^ stream_key[n % len(stream_key)] ^ prev
        words.append(d & M32)
        prev = e
    return words


# ─────────── 与 vellum.cpp 逐语义对齐的 Python 解释器 ───────────
def vm_run(words, in_buf, limit=400000):
    """words 为**明文**指令流；返回 (halted, steps, M)。"""
    M = [0] * 16
    acc = 0
    pc = 0
    steps = 0
    halted = False
    n = len(words)
    while 0 <= pc < n and steps < limit:
        w = words[pc] & M32
        op = (w >> 24) & 0xFF
        d = (w >> 20) & 0xF
        s = (w >> 16) & 0xF
        imm = w & 0xFFFF
        steps += 1
        jumped = False
        if op == OP_SET:
            M[d] = imm & M32
        elif op == OP_SETH:
            M[d] = ((M[d] & 0xFFFF) | (imm << 16)) & M32
        elif op == OP_CPY:
            M[d] = M[s]
        elif op == OP_GETA:
            acc = M[d]
        elif op == OP_PUTA:
            M[d] = acc & M32
        elif op == OP_GETM:
            acc = in_buf[imm] if imm < len(in_buf) else 0
        elif op == OP_ADDI:
            acc = (acc + imm) & M32
        elif op == OP_MULK:
            acc = (acc * imm) & M32
        elif op == OP_XORR:
            acc = (acc ^ M[s]) & M32
        elif op == OP_ANDR:
            acc = (acc & M[s]) & M32
        elif op == OP_ORR:
            acc = (acc | M[s]) & M32
        elif op == OP_ADDR:
            acc = (acc + M[s]) & M32
        elif op == OP_SUBR:
            acc = (acc - M[s]) & M32
        elif op == OP_SHL:
            acc = (acc << (imm & 0x1F)) & M32
        elif op == OP_SHR:
            acc = (acc >> (imm & 0x1F)) & M32
        elif op == OP_ROL8:
            v = acc & 0xFF
            r = imm & 7
            acc = ((v << r) | (v >> (8 - r))) & 0xFF          # 循环左移
        elif op == OP_ROR8:
            v = acc & 0xFF
            r = imm & 7
            acc = ((v >> r) | (v << (8 - r))) & 0xFF          # 循环右移
        elif op == OP_XORI:
            acc = (acc ^ imm) & M32
        elif op == OP_ANDI:
            acc = (acc & imm) & M32
        elif op == OP_JMP:
            pc = imm
            jumped = True
        elif op == OP_JZ:
            if acc == 0:
                pc = imm
                jumped = True
        elif op == OP_JNZ:
            if acc != 0:
                pc = imm
                jumped = True
        elif op == OP_HALT:
            halted = True
            break
        else:
            return False, steps, M
        if not jumped:
            pc += 1
    return halted, steps, M


def vm_seed(enc_words, in_buf, nbytes=NB, limit=400000):
    """解密 + 执行，输出单元 M8..M15 → 小端 32 位 → nbytes 字节。"""
    words = chain_decode(enc_words)
    ok, steps, M = vm_run(words, in_buf, limit)
    if not ok:
        return None
    out = bytearray()
    for i in range(nbytes):
        out.append((M[OUT_BASE + i // 4] >> (8 * (i % 4))) & 0xFF)
    return bytes(out)


def encode_program(marker_len, salt_len, nbytes=NB):
    words = build_program(marker_len, salt_len, nbytes)
    enc_words = chain_encode(words)
    raw = b"".join(struct.pack("<I", w) for w in enc_words)
    return words, enc_words, raw


# ───────────────────────── 输出 C 头 ─────────────────────────
def c_array(name, data):
    rows = []
    for i in range(0, len(data), 12):
        rows.append("    " + ", ".join("0x%02X" % b for b in data[i:i + 12]) + ",")
    return "static const uint8_t %s[] = {\n%s\n};\n" % (name, "\n".join(rows))


def selftest():
    ok = True

    # ① SET/SETH 32 位往返（守护旧版"只写高 16 位"缺陷）
    t = [enc(OP_SET, d=3, imm=0), enc(OP_SETH, d=3, imm=0),
         enc(OP_SET, d=3, imm=0xBEEF), enc(OP_SETH, d=3, imm=0xDEAD), enc(OP_HALT)]
    h, st, M = vm_run(t, b"")
    print("SET/SETH   M3 = 0x%08X (期望 0xDEADBEEF)" % M[3])
    if not h or M[3] != 0xDEADBEEF:
        print("FAIL: SET/SETH 32 位往返失败"); ok = False

    # ② 绝对跳转：JZ 命中 + JMP 后不回退（守护旧版偏移差 1）
    t = [enc(OP_SET, d=1, imm=0), enc(OP_GETA, d=1), enc(OP_JZ, imm=4),   # acc=0 → 跳 4
         enc(OP_HALT),                                                     # 3 被跳过
         enc(OP_SET, d=2, imm=0x1234), enc(OP_HALT)]                       # 4
    h, st, M = vm_run(t, b"")
    print("JZ 绝对跳转 M2 = 0x%04X (期望 0x1234)" % M[2])
    if not h or M[2] != 0x1234:
        print("FAIL: 绝对跳转失败"); ok = False

    # ③ 真程序：HALT + 派生值 == 纯函数
    words, enc_words, raw = encode_program(len(MARKER_REAL), len(SALT_KEY), NB)
    in_real = build_input(MARKER_REAL, SALT_KEY)
    in_decoy = build_input(MARKER_DECOY, SALT_KEY)
    want = derive_key(MARKER_REAL, SALT_KEY, NB)
    got = vm_seed(enc_words, in_real, NB)
    halted, steps, M = vm_run(chain_decode(enc_words), in_real)
    print("VM words=%d bytes=%d steps=%d halted=%s" % (len(words), len(raw), steps, halted))
    print("python derive = %s" % want.hex())
    print("vm     derive = %s" % (got.hex() if got else "None"))
    if not halted:
        print("FAIL: VM 未 HALT"); ok = False
    if got != want:
        print("FAIL: VM 派生值 != 纯函数"); ok = False

    # ④ 诱饵不同
    decoy_want = derive_key(MARKER_DECOY, SALT_KEY, NB)
    decoy_got = vm_seed(enc_words, in_decoy, NB)
    print("vm     decoy  = %s" % (decoy_got.hex() if decoy_got else "None"))
    if decoy_got != decoy_want:
        print("FAIL: 诱饵输入派生值 != 纯函数"); ok = False
    if decoy_got == want:
        print("FAIL: 诱饵与真身派生值相同"); ok = False

    # ⑤ 标记不进字节码：明文程序里不得出现真标记的 ASCII 或 UTF-16 片段
    joined = b"".join(struct.pack("<I", w) for w in words)
    for probe in (MARKER_REAL, MARKER_REAL.decode().encode("utf-16-le")):
        if probe in joined:
            print("FAIL: 字节码里出现标记片段"); ok = False
    print("SELFTEST", "OK" if ok else "FAILED")
    return ok


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "app/jni/kkl5_vm_program.h"
    if not selftest():
        sys.exit(1)
    _, _, raw = encode_program(len(MARKER_REAL), len(SALT_KEY), NB)
    key = derive_key(MARKER_REAL, SALT_KEY, NB)
    text = ["/* 自动生成：python tools/gen_kkl5_vm_program.py —— 请勿手改。 */\n"]
    text.append("#ifndef KKL5_VM_PROGRAM_H\n#define KKL5_VM_PROGRAM_H\n\n#include <stdint.h>\n\n")
    text.append(c_array("kKkl5VmProgram", raw))
    text.append("#define KKL5_VM_PROGRAM_BYTES %d\n" % len(raw))
    text.append(c_array("kKkl5VmStreamKey", STREAM_KEY))
    text.append("#define KKL5_VM_STREAM_KEY_LEN %d\n" % len(STREAM_KEY))
    text.append(c_array("kKkl5VmChainIV", struct.pack("<I", CHAIN_IV)))
    text.append("#define KKL5_VM_CHAIN_IV_LEN 4\n\n")
    text.append("#endif\n")
    with open(out, "w", encoding="utf-8") as f:
        f.write("".join(text))
    print("写入", out)
    print("KKL5 主钥（供 server.py）= %s" % key.hex())
    print("  SM4 key = %s" % key[:16].hex())
    print("  AES key = %s" % key[16:].hex())


if __name__ == "__main__":
    main()
