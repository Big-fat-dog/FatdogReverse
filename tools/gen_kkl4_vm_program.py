# -*- coding: utf-8 -*-
"""KKL4 锁妖塔：VMP 字节码生成器（栈式虚拟机 · 链式解码 · 子程序调用）。

把"从真标记 + salt 派生 32 字节主钥（16B AES 密钥 + 16B CTR 初值）"的门禁逻辑
编译成一台自造**栈式**虚拟机的字节码，再用**链式（CBC 式）**密钥流加密，写进
app/jni/kkl4_vm_program.h。

与 KKL3/KL5 的 VM 刻意**非同构**（同一款靶场里三个 VM 不能长得一样）：

| 维度 | KKL4（本文件） | KKL3（gen_kkl3_vm_program.py） | KKL5 |
|---|---|---|---|
| 架构 | **栈机 + 4 通用寄存器（混合）** | 16 寄存器机 | 寄存器机 |
| 指令编码 | `(op<<28) \\| imm28`，op 在高半字节 | `(imm16<<16)\\|(rd<<12)\\|(rs<<8)\\|op` | `(op<<24)\\|imm16` |
| 字节码解密 | **链式**：key_{n+1}=rotl32(key,9)^dec_n^C（CBC 式，逐条依赖前一条） | 周期滚动异或（可整段解） | 周期滚动异或 |
| 取操作数 | **GETM idx** 从运行时输入缓冲读（标记不进字节码） | 立即数内联 | 立即数内联 |
| 控制流 | 绝对跳转 + **CALL/RET 子程序**（独立返回栈） | 绝对跳转，无子程序 | 相对偏移（且偏移约定不一致，VM 无法 HALT） |
| 派生式 | `rol8(x,3)` + 系数 0x51/0x37/0x23 + `si>>1` + `mi+i*7` | `ror8` + 0x3D/0x29/0x1B | `rol8` + 0x1F/0x2B/0x11 |
| 输出 | 32 字节（AES key + CTR iv） | 16 字节 | 16 字节 |

真标记 `Fatdog_dread` **不以任何形式**出现在字节码里：程序只含 `GETM idx`，
标记字节由门面在运行时从 .data 的 UTF-16 数组喂入，因此静态段/字节码里都没有明文。
明文诱饵 `Fatdog_dream`（仅差末位一字）躺 .rodata，用它拼出的输入派生出的主钥
服务端不认（403）。

自测（默认开）：生成器内嵌一个与 obsidian.cpp 逐语义对齐的 Python 解释器，
跑真程序必须 HALT 且 32B 输出 == 纯函数派生值；换诱饵输入派生值必须不同。
"""
import struct
import sys

# ───────────────────────── 指令集（op 占高 4 位，imm 占低 28 位） ─────────────────────────
OP_PUSH = 0x0   # 压入 imm20
OP_GETM = 0x1   # 压入 输入缓冲[imm8]
OP_POPK = 0x2   # 寄存器[imm4] = 弹出
OP_PUSHR = 0x3  # 压入 寄存器[imm4]
OP_ADD = 0x4    # b=弹,a=弹,压(a+b)
OP_SUB = 0x5    # 压(a-b)
OP_XOR = 0x6
OP_AND = 0x7
OP_MULK = 0x8   # 压(弹出 * imm20)
OP_ROL8 = 0x9   # 压(rol8(弹出 & 0xFF, imm3))
OP_SHL = 0xA    # 压((弹出 << imm5) & 0xFFFFFFFF)
OP_SHR = 0xB    # 压(弹出 >> imm5)
OP_CALL = 0xC   # 返回栈压 pc+1；pc = imm16
OP_RET = 0xD    # pc = 返回栈弹
OP_JZ = 0xE     # v=弹；若 v==0 则 pc=imm16
OP_HALT = 0xF

MARKER_REAL = b"Fatdog_dread"
MARKER_DECOY = b"Fatdog_dream"     # 明文诱饵：仅末位 d/m 一字之差
SALT_KEY = b"|kkl4_tower"
NB = 32                            # 派生字节数：16B AES key + 16B CTR iv
CHAIN_SEED = 0x4B1D9A37            # 链式解码初始密钥
CHAIN_MIX = 0x7F4A7C15             # 链式步进常量


def enc(op, imm=0):
    return ((op & 0xF) << 28) | (imm & 0x0FFFFFFF)


def rotl32(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


# ───────────────────── 服务端同款纯函数派生 ─────────────────────
def mix_byte(marker, salt, i):
    mi = marker[i % len(marker)]
    si = salt[i % len(salt)]
    x = (mi * 0x51 + si * 0x37 + i * 0x23) & 0xFF
    x ^= (si >> 1) & 0xFF
    x = ((x << 3) | (x >> 5)) & 0xFF          # rol8 3
    return (x ^ ((mi + i * 7) & 0xFF)) & 0xFF


def derive_key(marker, salt, n=NB):
    return bytes(mix_byte(marker, salt, i) for i in range(n))


def build_input(marker, salt):
    """运行时输入缓冲布局：marker 字节 ‖ salt 字节。"""
    return bytes(marker) + bytes(salt)


# ───────────────────────── 字节码构造 ─────────────────────────
def _mix_routine():
    """子程序：入口数据栈顶→底 = [mi, si, i]；出口压回 1 个字节（结果）。"""
    r = []
    r += [enc(OP_POPK, 0), enc(OP_POPK, 1), enc(OP_POPK, 2)]          # R0=mi R1=si R2=i
    # x = (R0*0x51 + R1*0x37 + R2*0x23) & 0xFF
    r += [enc(OP_PUSHR, 0), enc(OP_MULK, 0x51)]
    r += [enc(OP_PUSHR, 1), enc(OP_MULK, 0x37), enc(OP_ADD)]
    r += [enc(OP_PUSHR, 2), enc(OP_MULK, 0x23), enc(OP_ADD)]
    r += [enc(OP_PUSH, 0xFF), enc(OP_AND)]
    # x ^= (R1 >> 1)
    r += [enc(OP_PUSHR, 1), enc(OP_SHR, 1), enc(OP_XOR)]
    # x = rol8(x, 3)
    r += [enc(OP_ROL8, 3)]
    # x ^= (R0 + R2*7) & 0xFF
    r += [enc(OP_PUSHR, 2), enc(OP_MULK, 7), enc(OP_PUSHR, 0), enc(OP_ADD)]
    r += [enc(OP_PUSH, 0xFF), enc(OP_AND), enc(OP_XOR)]
    r += [enc(OP_RET)]
    return r


def _junk(v):
    """无害垃圾：PUSH v; POPK R3（净零栈效应，只污染未用寄存器 R3）。"""
    return [enc(OP_PUSH, v & 0xFFFFF), enc(OP_POPK, 3)]


def _decoy_routine():
    """不可达诱饵子程序：垃圾运算 + RET，制造静态分析里的"第二条路"。"""
    r = []
    r += [enc(OP_GETM, 0), enc(OP_MULK, 0xC3), enc(OP_ROL8, 5), enc(OP_POPK, 3)]
    r += [enc(OP_PUSH, 0x5A5A), enc(OP_XOR), enc(OP_PUSH, 0xFFFF), enc(OP_AND)]
    r += [enc(OP_POPK, 3), enc(OP_RET)]
    return r


def build_program(marker_len, salt_len, nbytes=NB):
    """
    程序布局：
        [prologue]  PUSH 9; JZ dead        （恒不跳，制造分支错觉）
        [rounds]    每轮：PUSH i; GETM si; GETM mi; CALL mix
        [HALT]
        [mix]       子程序（供 CALL）
        [dead]      死块：垃圾 + HALT
        [decoy]     诱饵子程序（不可达）
    """
    prog = []

    # ── 序言：一个恒不成立的条件跳转（JZ 弹出 9，9 != 0）
    prog.append(enc(OP_PUSH, 9))
    jz_pos = len(prog)
    prog.append(enc(OP_JZ, 0))                     # 目标稍后回填

    # ── 主体：nbytes 轮，每轮一次 CALL 到共享子程序
    for i in range(nbytes):
        mi_idx = i % marker_len
        si_idx = marker_len + (i % salt_len)
        prog += [enc(OP_PUSH, i), enc(OP_GETM, si_idx), enc(OP_GETM, mi_idx)]
        prog.append(enc(OP_CALL, 0))               # 目标稍后回填
        if i % 6 == 3:
            prog += _junk(0x11 * (i + 1))

    prog.append(enc(OP_HALT))

    mix_addr = len(prog)
    prog += _mix_routine()

    dead_addr = len(prog)
    prog += _junk(0x7E) + _junk(0x2B) + [enc(OP_HALT)]

    prog += _decoy_routine()

    # 回填跳转目标
    prog[jz_pos] = enc(OP_JZ, dead_addr)
    call_targets = [k for k in range(len(prog)) if False]
    # CALL 指令在主体里；顺序回填到 mix_addr（序言之后、HALT 之前，每 5 词一条）
    k = 2
    for i in range(nbytes):
        prog[k + 3] = enc(OP_CALL, mix_addr)
        k += 4
        if i % 6 == 3:
            k += 2
    return prog


# ─────────── 与 obsidian.cpp 逐语义对齐的 Python 解释器 ───────────
def chain_decode(enc_words, seed=CHAIN_SEED):
    words = []
    k = seed & 0xFFFFFFFF
    for e in enc_words:
        d = (e ^ k) & 0xFFFFFFFF
        words.append(d)
        k = rotl32(k, 9) ^ d ^ CHAIN_MIX
        k &= 0xFFFFFFFF
    return words


def vm_run(enc_words, in_buf, seed=CHAIN_SEED, limit=200000):
    """返回 (halted, steps, 数据栈)。"""
    words = chain_decode(enc_words, seed)
    regs = [0] * 4
    st = []
    rstack = []
    pc = 0
    steps = 0
    halted = False
    n = len(words)
    while 0 <= pc < n and steps < limit:
        w = words[pc]
        op = (w >> 28) & 0xF
        imm = w & 0x0FFFFFFF
        steps += 1
        jumped = False
        if op == OP_PUSH:
            st.append(imm & 0xFFFFF)
        elif op == OP_GETM:
            idx = imm & 0xFF
            st.append(in_buf[idx] if idx < len(in_buf) else 0)
        elif op == OP_POPK:
            regs[imm & 0xF] = st.pop() & 0xFFFFFFFF
        elif op == OP_PUSHR:
            st.append(regs[imm & 0xF])
        elif op == OP_ADD:
            b = st.pop(); a = st.pop(); st.append((a + b) & 0xFFFFFFFF)
        elif op == OP_SUB:
            b = st.pop(); a = st.pop(); st.append((a - b) & 0xFFFFFFFF)
        elif op == OP_XOR:
            b = st.pop(); a = st.pop(); st.append((a ^ b) & 0xFFFFFFFF)
        elif op == OP_AND:
            b = st.pop(); a = st.pop(); st.append((a & b) & 0xFFFFFFFF)
        elif op == OP_MULK:
            st.append((st.pop() * imm) & 0xFFFFFFFF)
        elif op == OP_ROL8:
            v = st.pop() & 0xFF
            r = imm & 7
            st.append(((v << r) | (v >> (8 - r))) & 0xFF)   # 循环左移
        elif op == OP_SHL:
            st.append((st.pop() << (imm & 0x1F)) & 0xFFFFFFFF)
        elif op == OP_SHR:
            st.append((st.pop() >> (imm & 0x1F)) & 0xFFFFFFFF)
        elif op == OP_CALL:
            rstack.append(pc + 1)
            pc = imm
            jumped = True
        elif op == OP_RET:
            pc = rstack.pop()
            jumped = True
        elif op == OP_JZ:
            v = st.pop()
            if v == 0:
                pc = imm
                jumped = True
        elif op == OP_HALT:
            halted = True
            break
        else:
            return False, steps, st
        if not jumped:
            pc += 1
    return halted, steps, st


def vm_seed(enc_words, in_buf, nbytes=NB, seed=CHAIN_SEED):
    ok, steps, st = vm_run(enc_words, in_buf, seed)
    if not ok or steps < 64 or len(st) < nbytes:
        return None
    return bytes(st[i] & 0xFF for i in range(nbytes))


def encode_program(marker_len, salt_len, nbytes=NB, seed=CHAIN_SEED):
    words = build_program(marker_len, salt_len, nbytes)
    # 链式加密：enc_n = dec_n ^ key_n ; key_{n+1} = rotl32(key_n,9) ^ dec_n ^ CHAIN_MIX
    enc_words = []
    k = seed & 0xFFFFFFFF
    for d in words:
        e = (d ^ k) & 0xFFFFFFFF
        enc_words.append(e)
        k = rotl32(k, 9) ^ d ^ CHAIN_MIX
        k &= 0xFFFFFFFF
    raw = b"".join(struct.pack("<I", w) for w in enc_words)
    return words, enc_words, raw


def c_array(name, data):
    rows = []
    for i in range(0, len(data), 12):
        rows.append("    " + ", ".join("0x%02X" % b for b in data[i:i + 12]) + ",")
    return "static const uint8_t %s[] = {\n%s\n};\n" % (name, "\n".join(rows))


def selftest():
    ok = True
    words, enc_words, raw = encode_program(len(MARKER_REAL), len(SALT_KEY), NB)
    in_real = build_input(MARKER_REAL, SALT_KEY)
    in_decoy = build_input(MARKER_DECOY, SALT_KEY)
    want = derive_key(MARKER_REAL, SALT_KEY, NB)

    halted, steps, st = vm_run(enc_words, in_real)
    got = vm_seed(enc_words, in_real, NB)
    print("VM words=%d bytes=%d steps=%d halted=%s" % (len(words), len(raw), steps, halted))
    print("python  derive = %s" % want.hex())
    print("vm      derive = %s" % (got.hex() if got else "None"))
    if not halted:
        print("FAIL: VM 未 HALT"); ok = False
    if got != want:
        print("FAIL: VM 派生值 != 纯函数"); ok = False
    if len(st) != NB:
        print("FAIL: 数据栈残留 %d（应恰为 %d）" % (len(st), NB)); ok = False
    decoy_want = derive_key(MARKER_DECOY, SALT_KEY, NB)
    decoy_got = vm_seed(enc_words, in_decoy, NB)
    print("vm      decoy  = %s" % (decoy_got.hex() if decoy_got else "None"))
    if decoy_got != decoy_want:
        print("FAIL: 诱饵输入派生值 != 纯函数"); ok = False
    if decoy_got == want:
        print("FAIL: 诱饵与真身派生值相同"); ok = False
    print("SELFTEST", "OK" if ok else "FAILED")
    return ok


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "app/jni/kkl4_vm_program.h"
    if not selftest():
        sys.exit(1)
    _, _, raw = encode_program(len(MARKER_REAL), len(SALT_KEY), NB)
    key = derive_key(MARKER_REAL, SALT_KEY, NB)
    text = ["/* 自动生成：python tools/gen_kkl4_vm_program.py —— 请勿手改。 */\n"]
    text.append("#ifndef KKL4_VM_PROGRAM_H\n#define KKL4_VM_PROGRAM_H\n\n#include <stdint.h>\n\n")
    text.append(c_array("kKkl4VmProgram", raw))
    text.append("#define KKL4_VM_PROGRAM_BYTES %d\n" % len(raw))
    text.append(c_array("kKkl4VmChainSeed", struct.pack("<I", CHAIN_SEED)))
    text.append("#define KKL4_VM_CHAIN_SEED_LEN 4\n\n")
    text.append("#endif\n")
    with open(out, "w", encoding="utf-8") as f:
        f.write("".join(text))
    print("写入", out)
    print("KKL4 主钥（供 server.py）= %s" % key.hex())


if __name__ == "__main__":
    main()
