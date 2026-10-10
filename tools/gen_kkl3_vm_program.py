# -*- coding: utf-8 -*-
"""KKL3 断魂谷：VMP 字节码生成器。

把"从真标记派生 SM4 主钥（16B）"的门禁逻辑编译成自定义寄存器 VM 字节码，
再用滚动异或密钥加密，写进 app/jni/kkl3_vm_program.h。

与 KKL5 的 VM 刻意为**非同构**（同一款靶场里两关的 VM 不能长得一样）：

| 维度 | KKL3（本文件） | KKL5（tools/gen_kkl5_vm_program.py） |
|---|---|---|
| 指令编码 | `(imm16<<16)|(rd<<12)|(rs<<8)|op` | `(op<<24)|imm16` |
| 跳转语义 | **绝对目标地址** | 相对偏移（且其生成器与解释器偏移约定不一致，VM 无法 HALT） |
| 派生式 | `ror8` + 系数 0x3D/0x29/0x1B | `rol8` + 系数 0x1F/0x2B/0x11 |
| 滚动密钥 | 0x57 起 39 字节 | 0x11 起 32 字节 |
| 循环 | 16 轮完全展开（每轮立即数内联） | 真循环 + 表选择链 |

真标记 `Fatdog_quell` 只以 **VM 立即数**的形式存在于（加密后的）字节码里；
诱饵 `mZ7~qB3#nV9!` 另生成一组程序，解出的主钥服务端不认（403）。

自测（--selftest，默认开）：生成器内嵌一个与 kkl3 lattice.cpp 逐语义对齐的
Python 解释器，跑一遍真程序必须 HALT 且 16B 输出 == 纯函数派生值。
"""
import struct
import sys

# ───────────────────────── 指令集 ─────────────────────────
OP_LDI = 0x01   # Rd = (Rd & 0xFFFF0000) | imm16
OP_LDIH = 0x02  # Rd = (Rd & 0x0000FFFF) | (imm16 << 16)
OP_MOV = 0x03   # Rd = Rs
OP_ADD = 0x04   # Rd += Rs
OP_ADDK = 0x05  # Rd += imm16
OP_SUB = 0x06
OP_SUBK = 0x07
OP_EOR = 0x08
OP_EORK = 0x09
OP_AND = 0x0A
OP_ANDK = 0x0B
OP_ORR = 0x0C
OP_SHL = 0x0D   # Rd <<= (imm8)
OP_SHR = 0x0E
OP_ROR = 0x0F   # Rd = ror8(Rd & 0xFF, imm8 & 7)
OP_MULK = 0x10  # Rd *= imm16
OP_CMP = 0x11   # R0 = (Rd == Rs)
OP_JMP = 0x12   # pc = imm16（绝对）
OP_JEQ = 0x13   # if (Rd == 0) pc = imm16
OP_JNE = 0x14   # if (Rd != 0) pc = imm16
OP_NOP = 0x15
OP_HALT = 0x16

MARKER_REAL = b"Fatdog_quell"
MARKER_DECOY = b"mZ7~qB3#nV9!"
SALT_KEY = b"|kkl3_valley"
ROLLING_KEY = bytes(((0x57 + i * 0x1D) & 0xFF) for i in range(39))


def enc(op, rd=0, rs=0, imm=0):
    return ((imm & 0xFFFF) << 16) | ((rd & 0xF) << 12) | ((rs & 0xF) << 8) | (op & 0xFF)


def ldi(rd, v):   return [enc(OP_LDI, rd, 0, v & 0xFFFF)]
def ldih(rd, v):  return [enc(OP_LDIH, rd, 0, (v >> 16) & 0xFFFF)]
def ldi32(rd, v): return ldi(rd, v) + ldih(rd, v)


# ───────────────────── 服务端同款纯函数派生 ─────────────────────
def mix_byte(marker, salt, i):
    mi = marker[i % len(marker)]
    si = salt[i % len(salt)]
    x = (mi * 0x3D + si * 0x29 + i * 0x1B) & 0xFF
    x ^= (si << 2) & 0xFF
    x = ((x >> 3) | (x << 5)) & 0xFF          # ror8 3
    return (x ^ mi ^ (i & 0x7F)) & 0xFF


def derive_key(marker, salt, n=16):
    return bytes(mix_byte(marker, salt, i) for i in range(n))


# ───────────────────────── 字节码构造 ─────────────────────────
def build_program(marker, salt, nbytes=16):
    """16 轮完全展开：每轮把一个派生字节插进对应输出字的对应位置。

    输出寄存器约定：R1..R{n/4} 依次装输出字；R8..R11 为工作寄存器；
    R14 恒 0（供虚假分支使用）。
    """
    code = []
    word_count = (nbytes + 3) // 4
    out_regs = [1 + w for w in range(word_count)]

    # 头部：R14 = 0，随后一个"虚假控制流"分支（恒跳，制造 IDA 里的分支错觉）
    code += ldi(14, 0)
    jeq_at = len(code)
    code.append(enc(OP_JEQ, 14, 0, 0))          # 恒成立 → 跳过下面一条
    code += ldi(15, 0x5A5A)                     # 死块
    body = len(code)
    code[jeq_at] = enc(OP_JEQ, 14, 0, body)

    for r in out_regs:
        code += ldi(r, 0)

    for i in range(nbytes):
        mi = marker[i % len(marker)]
        si = salt[i % len(salt)]
        w = i // 4
        sh = (i % 4) * 8
        out = out_regs[w]

        # R8 = (mi*0x3D + si*0x29 + i*0x1B) & 0xFF
        code += ldi(8, mi) + [enc(OP_MULK, 8, 0, 0x3D)]
        code += ldi(9, si) + [enc(OP_MULK, 9, 0, 0x29)]
        code += [enc(OP_ADD, 8, 9, 0), enc(OP_ADDK, 8, 0, (i * 0x1B) & 0xFFFF),
                 enc(OP_ANDK, 8, 0, 0xFF)]
        # R8 ^= (si << 2) & 0xFF
        code += ldi(9, si) + [enc(OP_SHL, 9, 0, 2), enc(OP_ANDK, 9, 0, 0xFF),
                              enc(OP_EOR, 8, 9, 0)]
        # R8 = ror8(R8, 3) ^ mi ^ (i & 0x7F)
        code += [enc(OP_ROR, 8, 0, 3), enc(OP_EORK, 8, 0, mi),
                 enc(OP_EORK, 8, 0, i & 0x7F)]

        # out = (out & ~(0xFF << sh)) | (R8 << sh)
        mask = (~(0xFF << sh)) & 0xFFFFFFFF
        code += [enc(OP_MOV, 10, out, 0)]
        code += ldi32(11, mask)
        code += [enc(OP_AND, 10, 11, 0), enc(OP_SHL, 8, 0, sh),
                 enc(OP_ORR, 10, 8, 0), enc(OP_MOV, out, 10, 0)]

    code.append(enc(OP_HALT))
    return code


# ─────────── 与 kkl3 lattice.cpp 逐语义对齐的 Python 解释器 ───────────
def vm_run_bytes(enc_bytes, rolling_key=ROLLING_KEY, limit=500000):
    """解密滚动异或字节码并解释执行，返回 (halted, steps, regs)。"""
    n = len(enc_bytes) // 4
    words = [0] * n
    for i, b in enumerate(enc_bytes):
        words[i // 4] |= (b ^ rolling_key[i % len(rolling_key)]) << ((i % 4) * 8)
    regs = [0] * 16
    pc = 0
    steps = 0
    halted = False
    while 0 <= pc < n and steps < limit:
        w = words[pc]
        op = w & 0xFF
        rs = (w >> 8) & 0xF
        rd = (w >> 12) & 0xF
        imm = (w >> 16) & 0xFFFF
        steps += 1
        jumped = False
        if op == OP_LDI:
            regs[rd] = (regs[rd] & 0xFFFF0000) | imm
        elif op == OP_LDIH:
            regs[rd] = (regs[rd] & 0xFFFF) | (imm << 16)
        elif op == OP_MOV:
            regs[rd] = regs[rs]
        elif op == OP_ADD:
            regs[rd] = (regs[rd] + regs[rs]) & 0xFFFFFFFF
        elif op == OP_ADDK:
            regs[rd] = (regs[rd] + imm) & 0xFFFFFFFF
        elif op == OP_SUB:
            regs[rd] = (regs[rd] - regs[rs]) & 0xFFFFFFFF
        elif op == OP_SUBK:
            regs[rd] = (regs[rd] - imm) & 0xFFFFFFFF
        elif op == OP_EOR:
            regs[rd] ^= regs[rs]
        elif op == OP_EORK:
            regs[rd] ^= imm
        elif op == OP_AND:
            regs[rd] &= regs[rs]
        elif op == OP_ANDK:
            regs[rd] &= imm
        elif op == OP_ORR:
            regs[rd] |= regs[rs]
        elif op == OP_SHL:
            regs[rd] = (regs[rd] << (imm & 0xFF)) & 0xFFFFFFFF
        elif op == OP_SHR:
            regs[rd] = (regs[rd] >> (imm & 0xFF)) & 0xFFFFFFFF
        elif op == OP_ROR:
            r = imm & 7
            v = regs[rd] & 0xFF
            regs[rd] = ((v >> r) | (v << (8 - r))) & 0xFF
        elif op == OP_MULK:
            regs[rd] = (regs[rd] * imm) & 0xFFFFFFFF
        elif op == OP_CMP:
            regs[0] = 1 if regs[rd] == regs[rs] else 0
        elif op == OP_JMP:
            pc = imm
            jumped = True
        elif op == OP_JEQ:
            if regs[rd] == 0:
                pc = imm
                jumped = True
        elif op == OP_JNE:
            if regs[rd] != 0:
                pc = imm
                jumped = True
        elif op == OP_NOP:
            pass
        elif op == OP_HALT:
            halted = True
            break
        else:
            return False, steps, regs
        if not jumped:
            pc += 1
    return halted, steps, regs


def vm_seed(enc_bytes, base_reg=1, nbytes=16, rolling_key=ROLLING_KEY):
    ok, steps, regs = vm_run_bytes(enc_bytes, rolling_key)
    if not ok or steps < 32:
        return None
    return bytes(((regs[base_reg + (i // 4)] >> ((i % 4) * 8)) & 0xFF) for i in range(nbytes))


def encode_program(marker, salt, nbytes, rolling_key):
    words = build_program(marker, salt, nbytes)
    raw = b"".join(struct.pack("<I", w) for w in words)
    enc_bytes = bytes(b ^ rolling_key[i % len(rolling_key)] for i, b in enumerate(raw))
    return words, enc_bytes


def c_array(name, data):
    rows = []
    for i in range(0, len(data), 12):
        rows.append("    " + ", ".join("0x%02X" % b for b in data[i:i + 12]) + ",")
    return "static const uint8_t %s[] = {\n%s\n};\n" % (name, "\n".join(rows))


def selftest():
    real_words, real_enc = encode_program(MARKER_REAL, SALT_KEY, 16, ROLLING_KEY)
    decoy_words, decoy_enc = encode_program(MARKER_DECOY, SALT_KEY, 16, ROLLING_KEY)
    want = derive_key(MARKER_REAL, SALT_KEY, 16)
    got = vm_seed(real_enc)
    ok = True
    print("VM words=%d bytes=%d" % (len(real_words), len(real_enc)))
    print("python  derive_key = %s" % want.hex())
    print("vm      derive_key = %s" % (got.hex() if got else "None"))
    if got != want:
        print("FAIL: VM 派生结果与纯函数不一致"); ok = False
    ok_, steps, _ = vm_run_bytes(real_enc)
    print("VM halted/ steps    = %s / %d" % (ok_, steps))
    if not ok_ or steps < 32:
        print("FAIL: VM 未正常 HALT"); ok = False
    decoy = vm_seed(decoy_enc)
    print("vm decoy seed      = %s" % (decoy.hex() if decoy else "None"))
    if decoy == want:
        print("FAIL: 诱饵派生值与真身相同"); ok = False
    print("SELFTEST", "OK" if ok else "FAILED")
    return ok, real_enc, decoy_enc, want


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "app/jni/kkl3_vm_program.h"
    ok, real_enc, decoy_enc, key = selftest()
    if not ok:
        sys.exit(1)

    text = ["/* 自动生成：python tools/gen_kkl3_vm_program.py —— 请勿手改。 */\n"]
    text.append("#ifndef KKL3_VM_PROGRAM_H\n#define KKL3_VM_PROGRAM_H\n\n#include <stdint.h>\n\n")
    text.append(c_array("kKkl3VmProgramEnc", real_enc))
    text.append("#define KKL3_VM_PROGRAM_BYTES %d\n" % len(real_enc))
    text.append(c_array("kKkl3VmDecoyEnc", decoy_enc))
    text.append("#define KKL3_VM_DECOY_BYTES %d\n" % len(decoy_enc))
    text.append(c_array("kKkl3VmRollingSeed", ROLLING_KEY))
    text.append("#define KKL3_VM_SEED_LEN %d\n\n" % len(ROLLING_KEY))
    text.append("#endif\n")
    with open(out, "w", encoding="utf-8") as f:
        f.write("".join(text))
    print("写入", out)
    print("SM4 主钥（供 server.py 比对）= %s" % key.hex())


if __name__ == "__main__":
    main()
