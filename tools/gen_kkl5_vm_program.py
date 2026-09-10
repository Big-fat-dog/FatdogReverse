# -*- coding: utf-8 -*-
"""KKL5 诛仙台：VMP 字节码生成器。

把"从标记派生 AES/HMAC 子钥"的门禁逻辑编译成自定义寄存器 VM 字节码，
再用滚动异或密钥加密，写进 app/jni/kkl5_vm_program.h。

对齐 360/商业壳思路：
  - 业务逻辑（onCreate 门禁的密钥派生）不以原生指令出现，而是 VM 字节码；
  - 解释器用 switch-case 实现，字节码加密存储，运行时逐条解密执行；
  - 真标记 Fatdog_ascend 只作为 VM 立即数存在；诱饵 Fatdog_ascent 另生成一组，
    服务端只认真标记派生出的签名（诱饵签名 403）。

VM 指令编码（32 位小端）：
    [15:12] Rd  [11:8] Rs  [7:0] opcode  [31:16] imm16

MOV 支持 32 位立即数：生成器发两条 MOV，分别设置低 16 位与高 16 位。
"""
import struct
import sys

OP_MOV = 0x01
OP_ADDI = 0x02
OP_XOR = 0x03
OP_XORI = 0x04
OP_AND = 0x05
OP_OR = 0x06
OP_SHL = 0x07
OP_SHR = 0x08
OP_ROL = 0x09
OP_ROR = 0x0A
OP_CMP = 0x10
OP_JMP = 0x11
OP_JZ = 0x12
OP_JNZ = 0x13
OP_ADD = 0x14
OP_SUB = 0x15
OP_MUL = 0x16
OP_NOP = 0x17
OP_HALT = 0x18

MARKER_REAL = b"Fatdog_ascend"
MARKER_DECOY = b"Fatdog_ascent"
SALT_AES = b"|kkl5_cipher"
SALT_MAC = b"|kkl5_ascension"
ROLLING_KEY = bytes(range(0x11, 0x31))


def enc(op, rd=0, rs=0, imm=0):
    # opcode 放最高字节，立即数放低 16 位（与 kkl5.cpp 解释器一致）
    return ((op & 0xFF) << 24) | (imm & 0xFFFF)


def mov32(rd, value):
    return [
        enc(OP_MOV, rd, 0, value & 0xFFFF),
        enc(OP_MOV, rd, 0, (value >> 16) & 0xFFFF),
    ]


def _mix_byte(marker, salt, i):
    mi = marker[i % len(marker)]
    si = salt[i % len(salt)]
    x = (mi * 0x1F + si * 0x2B + i * 0x11) & 0xFF
    x ^= (mi << 1) & 0xFF
    x = ((x << 3) | (x >> 5)) & 0xFF
    return (x ^ si) & 0xFF


def derive_key(marker, salt, n):
    return bytes(_mix_byte(marker, salt, i) for i in range(n))


def expected_aes_key(marker=MARKER_REAL, salt=SALT_AES):
    return derive_key(marker, salt, 16)


def expected_mac_key(marker=MARKER_REAL, salt=SALT_MAC):
    return derive_key(marker, salt, 32)


def _select_byte(code, table_value_reg, index_reg, table):
    """把 table[index] 选进 table_value_reg：命中即赋值并跳到链尾。"""
    jumps = []
    for idx, b in enumerate(table):
        code += mov32(14, idx)
        code.append(enc(OP_CMP, index_reg, 14, 0))
        skip = len(code)
        code.append(enc(OP_JZ, 0, 0, 0))
        code += mov32(table_value_reg, b)
        jump = len(code)
        code.append(enc(OP_JMP, 0, 0, 0))
        jumps.append((skip, jump))
    end = len(code)
    for skip, jump in jumps:
        code[skip] = enc(OP_JZ, 0, 0, jump - skip + 1)
        code[jump] = enc(OP_JMP, 0, 0, end - jump - 1)


def build_program(marker, salt, nbytes):
    """纯寄存器派生：每轮算一个字节，插进对应的 32 位输出寄存器。"""
    code = []
    word_count = (nbytes + 3) // 4
    out_regs = [1 + w for w in range(word_count)]
    for w in range(word_count):
        code += mov32(out_regs[w], 0)

    loop = len(code)
    code += mov32(8, 0)                            # V8 = i
    code += mov32(12, nbytes)
    code.append(enc(OP_CMP, 8, 12, 0))
    jz_at = len(code)
    code.append(enc(OP_JZ, 0, 0, 0))

    # mi = marker[i % len(marker)]
    code += mov32(9, len(marker))
    code += mov32(10, 0)
    code.append(enc(OP_ADD, 10, 8, 0))
    code.append(enc(OP_AND, 10, 9, 0))
    code += mov32(11, 0)
    _select_byte(code, 11, 10, marker)

    # si = salt[i % len(salt)]
    code += mov32(9, len(salt))
    code += mov32(10, 0)
    code.append(enc(OP_ADD, 10, 8, 0))
    code.append(enc(OP_AND, 10, 9, 0))
    code += mov32(13, 0)
    _select_byte(code, 13, 10, salt)

    # k = (((mi*31 + si*43 + i*17) ^ (mi*2)) rol8 3) ^ si
    code.append(enc(OP_MUL, 11, 0, 0x1F))
    code.append(enc(OP_MUL, 13, 0, 0x2B))
    code.append(enc(OP_ADD, 11, 13, 0))
    code += mov32(9, 0)
    code.append(enc(OP_ADD, 9, 8, 0))
    code.append(enc(OP_MUL, 9, 0, 0x11))
    code.append(enc(OP_ADD, 11, 9, 0))
    code.append(enc(OP_AND, 11, 0, 0xFF))
    code.append(enc(OP_ROL, 11, 0, 3))
    code.append(enc(OP_XOR, 11, 13, 0))

    # j = i & 3，按 j 写入对应字的对应字节
    code += mov32(14, i_and_3 := 3)
    code += mov32(15, 0)
    code.append(enc(OP_ADD, 15, 8, 0))
    code.append(enc(OP_AND, 15, 14, 0))            # V15 = i & 3
    for w in range(word_count):
        code += mov32(12, w)
        code.append(enc(OP_CMP, 15, 12, 0))
        skip = len(code)
        code.append(enc(OP_JZ, 0, 0, 0))
        code += mov32(12, 0xFF << (w * 8))
        code += mov32(13, (~(0xFF << (w * 8))) & 0xFFFFFFFF)
        code.append(enc(OP_AND, out_regs[w], 13, 0))
        code.append(enc(OP_SHL, 11, 0, w * 8))
        code.append(enc(OP_OR, out_regs[w], 11, 0))
        code[skip] = enc(OP_JZ, 0, 0, len(code) - skip - 1)

    code.append(enc(OP_ADDI, 8, 0, 1))
    code.append(enc(OP_JMP, 0, 0, 0))
    jmp_at = len(code) - 1
    code[jmp_at] = enc(OP_JMP, 0, 0, loop - jmp_at - 1)
    code[jz_at] = enc(OP_JZ, 0, 0, len(code) - jz_at - 1)
    code.append(enc(OP_HALT))
    return code


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


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "app/jni/kkl5_vm_program.h"
    real_words, real_enc = encode_program(MARKER_REAL, SALT_AES, 16, ROLLING_KEY)
    mac_words, mac_enc = encode_program(MARKER_REAL, SALT_MAC, 32, ROLLING_KEY)
    decoy_words, decoy_enc = encode_program(MARKER_DECOY, SALT_AES, 16, ROLLING_KEY)
    aes_key = expected_aes_key()
    mac_key = expected_mac_key(MARKER_REAL, SALT_MAC)
    print("VMP aes_key=%s" % aes_key.hex())
    print("VMP mac_key=%s" % mac_key.hex())
    print("VMP decoy_key=%s" % derive_key(MARKER_DECOY, SALT_AES, 16).hex())
    print("VMP real_words=%d real_bytes=%d" % (len(real_words), len(real_enc)))

    text = ["/* 自动生成：python tools/gen_kkl5_vm_program.py —— 请勿手改。 */\n"]
    text.append("#ifndef KKL5_VM_PROGRAM_H\n#define KKL5_VM_PROGRAM_H\n\n#include <stdint.h>\n\n")
    text.append(c_array("kKkl5VmProgramEnc", real_enc))
    text.append("#define KKL5_VM_PROGRAM_WORDS %d\n" % len(real_words))
    text.append("#define KKL5_VM_PROGRAM_BYTES %d\n" % len(real_enc))
    text.append(c_array("kKkl5VmDecoyEnc", decoy_enc))
    text.append("#define KKL5_VM_DECOY_BYTES %d\n" % len(decoy_enc))
    text.append(c_array("kKkl5VmMacEnc", mac_enc))
    text.append("#define KKL5_VM_MAC_BYTES %d\n" % len(mac_enc))
    text.append("#define KKL5_VM_MAC_WORDS %d\n" % len(mac_words))
    text.append(c_array("kKkl5VmExpectAes", aes_key))
    text.append(c_array("kKkl5VmExpectMac", mac_key))
    text.append(c_array("kKkl5VmRollingKey", ROLLING_KEY))
    text.append("#define KKL5_VM_KEY_LEN %d\n\n" % len(ROLLING_KEY))
    text.append("#endif\n")
    with open(out, "w", encoding="utf-8") as f:
        f.write("".join(text))
    print("写入", out)


if __name__ == "__main__":
    main()
