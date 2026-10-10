# -*- coding: utf-8 -*-
"""KKL3 断魂谷：5 个 so 的生成器。

        ┌── libbeacon.so   JNI 门面（唯一暴露 Java_ 符号）；dlsym 其余四个内核
        ├── liblattice.so  虚拟机内核：滚动异或解密 + 寄存器 VM 解释执行
        ├── libbasalt.so   SM4-ECB(PKCS#7) 加解密 + 十六进制编码
        ├── libingot.so    MD5 摘要（取数签名，零 HMAC）
        └── libharbor.so   完整性守卫：TracerPid / 段权限 / 断点 / 模拟器（阈值 2）

五者缺一：门面 dlsym 拿不到内核指针 → 自检报"内核缺失"、签名返回空 → 服务端 403。

数据链（全网络取数，`GET /api/kkl3`）：
    seed(16B) = VM(真标记 Fatdog_quell + "|kkl3_valley")      ← 只有 VM 字节码里有标记
    enc       = hex( SM4-ECB(seed, "page=N&ts=T") )
    sign      = md5( hex(seed) + enc )
服务端：SM4-ECB 解 enc 必须还原出 "page=N&ts=T"，且 sign 必须对得上。

标记：真 = Fatdog_quell（UTF-16 码元作 VM 立即数，加密字节码里不可见）
      假 = mZ7~qB3#nV9!（诱饵程序另派生一组主钥，服务端不认）

用法：
    python gen_kkl3.py                     # 生成 5 个 so 源 + 自测
    python gen_kkl3.py --selftest          # 只跑自测
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
JNI = os.path.join(HERE, 'app', 'jni')

# ─────────────── 与 tools/gen_kkl3_vm_program.py 的共享事实（硬约束） ───────────────
MARKER = b"Fatdog_quell"
DECOY = b"mZ7~qB3#nV9!"
SALT = b"|kkl3_valley"
PAGES, PER_PAGE, SEED = 100, 10, 20260916

sys.path.insert(0, os.path.join(HERE, 'tools'))
sys.path.insert(0, os.path.join(HERE, 'tools', ''))
import gen_kkl3_vm_program as vmgen  # noqa: E402

assert vmgen.MARKER_REAL == MARKER and vmgen.MARKER_DECOY == DECOY and vmgen.SALT_KEY == SALT, \
    '标记/salt 与 VM 生成器不一致'
TRUE_SEED = vmgen.derive_key(MARKER, SALT, 16)


# ─────────────────────────── 纯 Python SM4（自测 + 供 server.py 参考） ───────────────────────────
SBOX = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
]
FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
M32 = 0xFFFFFFFF


def _rotl(x, n):
    x &= M32
    return ((x << n) | (x >> (32 - n))) & M32


def _ck(i):
    b = [((4 * i + j) * 7) & 0xFF for j in range(4)]
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]


def _tau(x):
    return ((SBOX[(x >> 24) & 0xFF] << 24) | (SBOX[(x >> 16) & 0xFF] << 16)
            | (SBOX[(x >> 8) & 0xFF] << 8) | SBOX[x & 0xFF])


def _t_fun(x):
    b = _tau(x)
    return b ^ _rotl(b, 2) ^ _rotl(b, 10) ^ _rotl(b, 18) ^ _rotl(b, 24)


def _tp_fun(x):
    b = _tau(x)
    return b ^ _rotl(b, 13) ^ _rotl(b, 23)


def sm4_keys(key):
    k = [int.from_bytes(key[i * 4:i * 4 + 4], 'big') ^ FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        nk = k[0] ^ _tp_fun(k[1] ^ k[2] ^ k[3] ^ _ck(i))
        rk.append(nk)
        k = [k[1], k[2], k[3], nk]
    return rk


def _sm4_block(rk, blk):
    x = [int.from_bytes(blk[i * 4:i * 4 + 4], 'big') for i in range(4)]
    for i in range(32):
        nx = x[0] ^ _t_fun(x[1] ^ x[2] ^ x[3] ^ rk[i])
        x = [x[1], x[2], x[3], nx]
    return b"".join((v & M32).to_bytes(4, 'big') for v in (x[3], x[2], x[1], x[0]))


def sm4_ecb_enc(key, data):
    rk = sm4_keys(key)
    pad = 16 - (len(data) % 16)
    data = data + bytes([pad]) * pad
    return b"".join(_sm4_block(rk, data[i:i + 16]) for i in range(0, len(data), 16))


def sm4_ecb_dec(key, data):
    if len(data) == 0 or len(data) % 16:
        return None
    rk = sm4_keys(key)[::-1]
    out = b"".join(_sm4_block(rk, data[i:i + 16]) for i in range(0, len(data), 16))
    pad = out[-1]
    if pad == 0 or pad > 16 or out[-pad:] != bytes([pad]) * pad:
        return None
    return out[:-pad]


# ─────────────────────────────── C++ 模板 ───────────────────────────────
VIS = '__attribute__((visibility("default")))'


def sbox_c():
    rows = []
    for i in range(0, 256, 16):
        rows.append('    ' + ', '.join('0x%02X' % b for b in SBOX[i:i + 16]) + ',')
    return 'static const uint8_t SBOX[256] = {\n' + '\n'.join(rows) + '\n};'


T_LATTICE = r'''/*
 * lattice —— 太玄之初 KKL3 断魂谷的虚拟机内核。
 *
 * 只做一件事：把滚动异或加密的自定义字节码解密后，用 switch 解释器逐条执行，
 * 把结果寄存器回吐给上层。真标记不在本文件出现——它只以 VM 立即数的形式
 * 潜伏在（加密的）字节码里。
 *
 * 指令编码： word = (imm16 << 16) | (rd << 12) | (rs << 8) | op
 * 跳转语义： 绝对目标（JMP/JEQ/JNE 的 imm16 即目标下标）
 * 由 tools/gen_kkl3_vm_program.py 生成对应字节码，二者必须同步修改。
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LT_VIS __attribute__((visibility("default")))

enum {
    VM_LDI = 0x01, VM_LDIH = 0x02, VM_MOV = 0x03, VM_ADD = 0x04, VM_ADDK = 0x05,
    VM_SUB = 0x06, VM_SUBK = 0x07, VM_EOR = 0x08, VM_EORK = 0x09, VM_AND = 0x0A,
    VM_ANDK = 0x0B, VM_ORR = 0x0C, VM_SHL = 0x0D, VM_SHR = 0x0E, VM_ROR = 0x0F,
    VM_MULK = 0x10, VM_CMP = 0x11, VM_JMP = 0x12, VM_JEQ = 0x13, VM_JNE = 0x14,
    VM_NOP = 0x15, VM_HALT = 0x16
};

/*
 * 解释执行。enc 为滚动异或密文，rolling 为其周期密钥。
 * 返回 true 表示正常 HALT；regs 为 16 个 32 位通用寄存器终值。
 */
extern "C" LT_VIS bool lt_vm_exec(const uint8_t *enc, size_t enc_len,
                                  const uint8_t *rolling, size_t roll_len,
                                  uint32_t regs[16], int *steps_out) {
    if (!enc || !rolling || roll_len == 0) return false;
    size_t n = enc_len / 4;
    if (n == 0) return false;
    uint32_t *words = (uint32_t *)calloc(n, sizeof(uint32_t));
    if (!words) return false;
    for (size_t i = 0; i < enc_len; i++) {
        uint8_t b = (uint8_t)(enc[i] ^ rolling[i % roll_len]);
        words[i / 4] |= ((uint32_t)b) << ((i % 4) * 8);
    }
    memset(regs, 0, sizeof(uint32_t) * 16);
    int pc = 0, steps = 0;
    bool halted = false;
    while (pc >= 0 && (size_t)pc < n && steps < 500000) {
        uint32_t w = words[pc];
        uint32_t op = w & 0xFFu, rs = (w >> 8) & 0xFu, rd = (w >> 12) & 0xFu, imm = (w >> 16) & 0xFFFFu;
        steps++;
        bool jumped = false;
        switch (op) {
        case VM_LDI:  regs[rd] = (regs[rd] & 0xFFFF0000u) | imm; break;
        case VM_LDIH: regs[rd] = (regs[rd] & 0x0000FFFFu) | (imm << 16); break;
        case VM_MOV:  regs[rd] = regs[rs]; break;
        case VM_ADD:  regs[rd] += regs[rs]; break;
        case VM_ADDK: regs[rd] += imm; break;
        case VM_SUB:  regs[rd] -= regs[rs]; break;
        case VM_SUBK: regs[rd] -= imm; break;
        case VM_EOR:  regs[rd] ^= regs[rs]; break;
        case VM_EORK: regs[rd] ^= imm; break;
        case VM_AND:  regs[rd] &= regs[rs]; break;
        case VM_ANDK: regs[rd] &= imm; break;
        case VM_ORR:  regs[rd] |= regs[rs]; break;
        case VM_SHL:  regs[rd] <<= (imm & 0xFF); break;
        case VM_SHR:  regs[rd] >>= (imm & 0xFF); break;
        case VM_ROR: {
            uint32_t r = imm & 7, v = regs[rd] & 0xFF;
            regs[rd] = ((v >> r) | (v << (8 - r))) & 0xFF;
            break;
        }
        case VM_MULK: regs[rd] *= imm; break;
        case VM_CMP:  regs[0] = (regs[rd] == regs[rs]) ? 1u : 0u; break;
        case VM_JMP:  pc = (int)imm; jumped = true; break;
        case VM_JEQ:  if (regs[rd] == 0) { pc = (int)imm; jumped = true; } break;
        case VM_JNE:  if (regs[rd] != 0) { pc = (int)imm; jumped = true; } break;
        case VM_NOP:  break;
        case VM_HALT: halted = true; break;
        default: free(words); return false;
        }
        if (halted) break;
        if (!jumped) pc++;
    }
    free(words);
    if (steps_out) *steps_out = steps;
    return halted;
}

/* 取 base_reg 起 nbytes 字节（小端拼装）作为派生结果。 */
extern "C" LT_VIS bool lt_vm_seed(const uint8_t *enc, size_t enc_len,
                                  const uint8_t *rolling, size_t roll_len,
                                  int base_reg, uint8_t *out, int nbytes) {
    uint32_t regs[16];
    if (!lt_vm_exec(enc, enc_len, rolling, roll_len, regs, 0)) return false;
    if (base_reg < 0 || base_reg * 4 + nbytes > 64) return false;
    for (int i = 0; i < nbytes; i++) {
        uint32_t v = regs[base_reg + (i / 4)];
        out[i] = (uint8_t)(v >> ((i % 4) * 8));
    }
    return true;
}

/* 诱饵：同一 VM 里程程序解出的另一组主钥（服务端不认）。 */
extern "C" LT_VIS void lt_decoy_head(uint8_t *out, int n) {
    for (int i = 0; i < n && i < 16; i++) out[i] = (uint8_t)(0x5A ^ (i * 0x13));
}
'''

T_BASALT = r'''/*
 * basalt —— 太玄之初 KKL3 断魂谷的国密原语内核。
 *
 * SM4 分组（128 位密钥 / 128 位分组，32 轮），ECB 模式 + PKCS#7 填充；
 * 另附十六进制编码。S 盒与系统参数按 GB/T 32907-2016 硬编码，
 * 轮常量 CK 用公式 ((4i+j)*7 mod 256) 现算，避免抄错表。
 */
#include <stdint.h>
#include <string.h>

#define BS_VIS __attribute__((visibility("default")))

__SBOX__

static const uint32_t FK[4] = {0xa3b1bac6u, 0x56aa3350u, 0x677d9197u, 0xb27022dcu};
static const uint8_t CK[128] = {
    0x00,0x07,0x0e,0x15, 0x1c,0x23,0x2a,0x31, 0x38,0x3f,0x46,0x4d, 0x54,0x5b,0x62,0x69,
    0x70,0x77,0x7e,0x85, 0x8c,0x93,0x9a,0xa1, 0xa8,0xaf,0xb6,0xbd, 0xc4,0xcb,0xd2,0xd9,
    0xe0,0xe7,0xee,0xf5, 0xfc,0x03,0x0a,0x11, 0x18,0x1f,0x26,0x2d, 0x34,0x3b,0x42,0x49,
    0x50,0x57,0x5e,0x65, 0x6c,0x73,0x7a,0x81, 0x88,0x8f,0x96,0x9d, 0xa4,0xab,0xb2,0xb9,
    0xc0,0xc7,0xce,0xd5, 0xdc,0xe3,0xea,0xf1, 0xf8,0xff,0x06,0x0d, 0x14,0x1b,0x22,0x29,
    0x30,0x37,0x3e,0x45, 0x4c,0x53,0x5a,0x61, 0x68,0x6f,0x76,0x7d, 0x84,0x8b,0x92,0x99,
    0xa0,0xa7,0xae,0xb5, 0xbc,0xc3,0xca,0xd1, 0xd8,0xdf,0xe6,0xed, 0xf4,0xfb,0x02,0x09,
    0x10,0x17,0x1e,0x25, 0x2c,0x33,0x3a,0x41, 0x48,0x4f,0x56,0x5d, 0x64,0x6b,0x72,0x79
};

static uint32_t bs_rot(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static uint32_t bs_tau(uint32_t x) {
    return ((uint32_t)SBOX[(x >> 24) & 0xFF] << 24) | ((uint32_t)SBOX[(x >> 16) & 0xFF] << 16)
         | ((uint32_t)SBOX[(x >> 8) & 0xFF] << 8)  | (uint32_t)SBOX[x & 0xFF];
}
static uint32_t bs_t(uint32_t x) {
    uint32_t b = bs_tau(x);
    return b ^ bs_rot(b, 2) ^ bs_rot(b, 10) ^ bs_rot(b, 18) ^ bs_rot(b, 24);
}
static uint32_t bs_tp(uint32_t x) {
    uint32_t b = bs_tau(x);
    return b ^ bs_rot(b, 13) ^ bs_rot(b, 23);
}
static uint32_t bs_ck(int i) {
    const uint8_t *p = CK + i * 4;
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void bs_keys(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t k[4];
    for (int i = 0; i < 4; i++) {
        k[i] = ((uint32_t)key[i * 4] << 24) | ((uint32_t)key[i * 4 + 1] << 16)
             | ((uint32_t)key[i * 4 + 2] << 8) | (uint32_t)key[i * 4 + 3];
        k[i] ^= FK[i];
    }
    for (int i = 0; i < 32; i++) {
        uint32_t nk = k[0] ^ bs_tp(k[1] ^ k[2] ^ k[3] ^ bs_ck(i));
        rk[i] = nk;
        k[0] = k[1]; k[1] = k[2]; k[2] = k[3]; k[3] = nk;
    }
}

static void bs_block(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16]) {
    uint32_t x[4];
    for (int i = 0; i < 4; i++)
        x[i] = ((uint32_t)in[i * 4] << 24) | ((uint32_t)in[i * 4 + 1] << 16)
             | ((uint32_t)in[i * 4 + 2] << 8) | (uint32_t)in[i * 4 + 3];
    for (int i = 0; i < 32; i++) {
        uint32_t nx = x[0] ^ bs_t(x[1] ^ x[2] ^ x[3] ^ rk[i]);
        x[0] = x[1]; x[1] = x[2]; x[2] = x[3]; x[3] = nx;
    }
    uint32_t o[4] = {x[3], x[2], x[1], x[0]};
    for (int i = 0; i < 4; i++) {
        out[i * 4]     = (uint8_t)(o[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(o[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(o[i] >> 8);
        out[i * 4 + 3] = (uint8_t)o[i];
    }
}

/* SM4-ECB 加密 + PKCS#7；返回密文长度，失败 -1。 */
extern "C" BS_VIS int bs_seal(const uint8_t key[16], const uint8_t *in, size_t len, uint8_t *out) {
    uint32_t rk[32];
    bs_keys(key, rk);
    size_t pad = 16 - (len % 16);
    size_t n = len + pad;
    for (size_t off = 0; off < n; off += 16) {
        uint8_t blk[16];
        for (int i = 0; i < 16; i++) {
            size_t p = off + i;
            blk[i] = p < len ? in[p] : (uint8_t)pad;
        }
        bs_block(rk, blk, out + off);
    }
    return (int)n;
}

/* SM4-ECB 解密 + 去 PKCS#7；返回明文长度，填充非法返回 -1。 */
extern "C" BS_VIS int bs_unseal(const uint8_t key[16], const uint8_t *in, size_t len, uint8_t *out) {
    if (len == 0 || (len % 16) != 0) return -1;
    uint32_t rk[32];
    bs_keys(key, rk);
    uint32_t rkrev[32];
    for (int i = 0; i < 32; i++) rkrev[i] = rk[31 - i];
    for (size_t off = 0; off < len; off += 16)
        bs_block(rkrev, in + off, out + off);
    uint8_t pad = out[len - 1];
    if (pad == 0 || pad > 16) return -1;
    for (size_t i = len - pad; i < len; i++)
        if (out[i] != pad) return -1;
    return (int)(len - pad);
}

/* 十六进制编码（小写）。 */
extern "C" BS_VIS void bs_hex(const uint8_t *in, size_t len, char *out) {
    const char *t = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = t[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = t[in[i] & 0xF];
    }
    out[len * 2] = '\0';
}
'''

T_INGOT = r'''/*
 * ingot —— 太玄之初 KKL3 断魂谷的摘要内核（MD5，零 HMAC）。
 *
 * 取数签名 = md5( hex(主钥) + 密文十六进制 )，由上层拼好后交给 ig_tally。
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define IG_VIS __attribute__((visibility("default")))

static const uint32_t IG_K[64] = {
    0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
    0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
    0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
    0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
    0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
    0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
    0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
    0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u
};
#define IG_RL(x,c) (((x) << (c)) | ((x) >> (32 - (c))))

extern "C" IG_VIS void ig_tally(const uint8_t *msg, size_t len, uint8_t out[16]) {
    uint32_t h[4] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
    size_t n = len + 1;
    size_t rem = n % 64;
    size_t pad = rem > 56 ? 120 - rem : 56 - rem;
    n += pad + 8;
    uint8_t *buf = (uint8_t *)calloc(n, 1);
    if (!buf) { memset(out, 0, 16); return; }
    memcpy(buf, msg, len);
    buf[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) buf[n - 8 + i] = (uint8_t)(bits >> (i * 8));
    for (size_t off = 0; off < n; off += 64) {
        uint32_t m[16];
        for (int i = 0; i < 16; i++)
            m[i] = ((uint32_t)buf[off + i * 4]) | ((uint32_t)buf[off + i * 4 + 1] << 8)
                 | ((uint32_t)buf[off + i * 4 + 2] << 16) | ((uint32_t)buf[off + i * 4 + 3] << 24);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        static const int S[64] = {
            7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
            5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
            4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
            6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
        };
        for (int i = 0; i < 64; i++) {
            uint32_t f; int g;
            if (i < 16)      { f = (b & c) | (~b & d);        g = i; }
            else if (i < 32) { f = (d & b) | (~d & c);        g = (5 * i + 1) % 16; }
            else if (i < 48) { f = b ^ c ^ d;                 g = (3 * i + 5) % 16; }
            else             { f = c ^ (b | ~d);              g = (7 * i) % 16; }
            uint32_t tmp = d;
            d = c; c = b;
            b = b + IG_RL(a + f + IG_K[i] + m[g], S[i]);
            a = tmp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    }
    free(buf);
    for (int i = 0; i < 4; i++) {
        out[i * 4]     = (uint8_t)h[i];
        out[i * 4 + 1] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(h[i] >> 24);
    }
}

extern "C" IG_VIS void ig_hex(const uint8_t *in, int n, char *out) {
    const char *t = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[i * 2] = t[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = t[in[i] & 0xF];
    }
    out[n * 2] = '\0';
}
'''

T_HARBOR = r'''/*
 * harbor —— 太玄之初 KKL3 断魂谷的完整性守卫（评分阈值制）。
 *
 * 四路（全部与第三方注入框架无关，只查"有没有人动过我的代码/运行环境"）：
 *   ① 调试器痕迹  /proc/self/status:TracerPid
 *   ② 段权限审计  自身映射里出现可写+可执行的段
 *   ③ 断点检测    本函数首 4 字节是否为 BRK / INT3 编码
 *   ④ 环境检测    ro.kernel.qemu 等模拟器特征
 *
 * 返回命中位掩码；上层按"命中数 >= 2"判风险，命中即静默投毒（签名密钥翻位）。
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/system_properties.h>

#define HB_VIS __attribute__((visibility("default")))

#define HIT_TRACE  1
#define HIT_SECTION 2
#define HIT_BREAK  4
#define HIT_EMU    8

static int hb_tracer(void) {
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return 0;
    char buf[4096];
    int n = (int)read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    char *p = strstr(buf, "TracerPid:");
    if (!p) return 0;
    return atoi(p + 10) != 0 ? 1 : 0;
}

static int hb_section(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    int hit = 0;
    while (fgets(line, sizeof(line), f)) {
        /* maps 行首即地址区间与权限位（如 r-xp / rw-p / rwxp）：
         * 出现 rwx = 同一段同时可写可执行，属可疑（反内存补丁）。 */
        if (strstr(line, "rwx")) { hit = 1; break; }
    }
    fclose(f);
    return hit;
}

static int hb_break(void) {
    uint32_t head = 0;
    memcpy(&head, (const void *)(uintptr_t)&hb_break, 4);
    if (head == 0xD4200000u) return 1;   /* BRK #0（AArch64） */
    if (head == 0xCCCCCCCCu || (head & 0xFF) == 0xCC) return 1; /* INT3（x86 兼容） */
    return 0;
}

static int hb_emulator(void) {
    char v[128];
    if (__system_property_get("ro.kernel.qemu", v) > 0 && v[0] == '1') return 1;
    if (__system_property_get("init.svc.qemud", v) > 0 && strcmp(v, "running") == 0) return 1;
    if (__system_property_get("ro.build.characteristics", v) > 0 && strstr(v, "emulator")) return 1;
    return 0;
}

extern "C" HB_VIS int hb_scan(int *detail) {
    int bits = 0;
    if (hb_tracer())   bits |= HIT_TRACE;
    if (hb_section())  bits |= HIT_SECTION;
    if (hb_break())    bits |= HIT_BREAK;
    if (hb_emulator()) bits |= HIT_EMU;
    if (detail) *detail = bits;
    return bits;
}
'''

T_BEACON = r'''/*
 * beacon —— 太玄之初 KKL3 断魂谷的 JNI 门面。
 *
 * 本 so 是全关**唯一**导出 Java_ 符号的库；它自身不含任何算法，
 * 全部内核靠 dlsym(RTLD_DEFAULT) 从其它四个 so 取：
 *     lt_vm_seed  （lattice）  虚拟机派生主钥
 *     bs_seal/bs_hex（basalt）国密 SM4-ECB 与十六进制
 *     ig_tally    （ingot）    MD5 摘要
 *     hb_scan     （harbor）   完整性守卫
 * 缺任一内核 → 自检报"内核缺失"，签名返回空串。
 */
#include <jni.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>

#include "kkl3_vm_program.h"

typedef bool (*fn_vm_seed)(const uint8_t *, size_t, const uint8_t *, size_t, int, uint8_t *, int);
typedef int  (*fn_seal)(const uint8_t *, const uint8_t *, size_t, uint8_t *);
typedef int  (*fn_unseal)(const uint8_t *, const uint8_t *, size_t, uint8_t *);
typedef void (*fn_hex)(const uint8_t *, size_t, char *);
typedef void (*fn_tally)(const uint8_t *, size_t, uint8_t *);
typedef void (*fn_ihex)(const uint8_t *, int, char *);
typedef int  (*fn_scan)(int *);

static fn_vm_seed g_vm = NULL;
static fn_seal    g_seal = NULL;
static fn_unseal  g_unseal = NULL;
static fn_hex     g_hex = NULL;
static fn_tally   g_tally = NULL;
static fn_ihex    g_ihex = NULL;
static fn_scan    g_scan = NULL;

static volatile int g_poisoned = 0;
static volatile int g_last_bits = 0;

static void bind_kernels(void) {
    if (g_vm) return;
    g_vm     = (fn_vm_seed)dlsym(RTLD_DEFAULT, "lt_vm_seed");
    g_seal   = (fn_seal)   dlsym(RTLD_DEFAULT, "bs_seal");
    g_unseal = (fn_unseal) dlsym(RTLD_DEFAULT, "bs_unseal");
    g_hex    = (fn_hex)    dlsym(RTLD_DEFAULT, "bs_hex");
    g_tally  = (fn_tally)  dlsym(RTLD_DEFAULT, "ig_tally");
    g_ihex   = (fn_ihex)   dlsym(RTLD_DEFAULT, "ig_hex");
    g_scan   = (fn_scan)   dlsym(RTLD_DEFAULT, "hb_scan");
}

static int kernel_missing(void) {
    return !(g_vm && g_seal && g_hex && g_tally && g_ihex && g_scan);
}

/* 翻位投毒：让本地派生出的主钥与服务端不再一致（服务端恒 403）。 */
static void poison(uint8_t *seed) {
    if (g_poisoned) return;
    seed[7] ^= 0x40;
    g_poisoned = 1;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl3Native_nativeStatus(JNIEnv *env, jclass) {
    bind_kernels();
    char buf[512];
    if (kernel_missing()) {
        snprintf(buf, sizeof(buf),
                 "内核编队不完整：虚拟机 %s / 国密 %s / 摘要 %s / 守卫 %s\n"
                 "lib/ 下五个 so 缺一不可。",
                 g_vm ? "在位" : "缺失", g_seal ? "在位" : "缺失",
                 g_tally ? "在位" : "缺失", g_scan ? "在位" : "缺失");
        return env->NewStringUTF(buf);
    }
    int bits = 0;
    g_scan(&bits);
    g_last_bits = bits;
    int hit = ((bits & 1) ? 1 : 0) + ((bits & 2) ? 1 : 0) + ((bits & 4) ? 1 : 0) + ((bits & 8) ? 1 : 0);
    snprintf(buf, sizeof(buf),
             "完整性自检（命中 %d 项，>=2 触发投毒）：\n"
             "  调试器痕迹 : %s\n"
             "  可写可执行段 : %s\n"
             "  断点痕迹   : %s\n"
             "  模拟器环境 : %s\n"
             "  主钥状态   : %s",
             hit,
             (bits & 1) ? "命中" : "安全", (bits & 2) ? "命中" : "安全",
             (bits & 4) ? "命中" : "安全", (bits & 8) ? "命中" : "安全",
             g_poisoned ? "已污染（服务端将拒绝）" : "正常");
    return env->NewStringUTF(buf);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl3Native_nativeSign(JNIEnv *env, jclass, jint page, jlong ts) {
    bind_kernels();
    if (kernel_missing()) return env->NewStringUTF("");
    int bits = 0;
    g_scan(&bits);
    g_last_bits = bits;
    int hit = ((bits & 1) ? 1 : 0) + ((bits & 2) ? 1 : 0) + ((bits & 4) ? 1 : 0) + ((bits & 8) ? 1 : 0);

    uint8_t seed[16];
    if (!g_vm(kKkl3VmProgramEnc, sizeof(kKkl3VmProgramEnc),
              kKkl3VmRollingSeed, KKL3_VM_SEED_LEN, 1, seed, 16)) {
        g_poisoned = 1;
        return env->NewStringUTF("");
    }
    if (hit >= 2) poison(seed);

    char payload[64];
    int pl = snprintf(payload, sizeof(payload), "page=%d&ts=%lld", (int)page, (long long)ts);

    uint8_t ct[128];
    int cl = g_seal(seed, (const uint8_t *)payload, (size_t)pl, ct);
    if (cl <= 0) { g_poisoned = 1; return env->NewStringUTF(""); }
    char enc[300];
    g_hex(ct, (size_t)cl, enc);

    char kh[40];
    g_ihex(seed, 16, kh);
    char msg[400];
    snprintf(msg, sizeof(msg), "%s%s", kh, enc);
    uint8_t mac[16];
    g_tally((const uint8_t *)msg, strlen(msg), mac);
    char sign[40];
    g_ihex(mac, 16, sign);

    char out[400];
    snprintf(out, sizeof(out), "%s|%s", enc, sign);
    return env->NewStringUTF(out);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Kkl3Native_nativePoisoned(JNIEnv *env, jclass) {
    (void)env;
    return g_poisoned ? 1 : 0;
}
'''


def c_header():
    return ('/* 自动生成：python gen_kkl3.py —— 请勿手改。 */\n'
            '/* 太玄之初 KKL3 断魂谷 · 五 so 编队（门面/虚拟机/国密/摘要/守卫）。 */\n\n')


def selftest():
    ok = True
    # ① SM4 标准向量（GB/T 32907-2016 附录 A）
    key = bytes.fromhex('0123456789abcdeffedcba9876543210')
    pt = bytes.fromhex('0123456789abcdeffedcba9876543210')
    ct = sm4_ecb_enc(key, pt)
    want = bytes.fromhex('681edf34d206965e86b3e94f536e4246')
    # ECB+PKCS7 会补一块，取前 16 字节比对
    print('SM4  vector = %s' % ct[:16].hex())
    print('SM4  expect = %s' % want.hex())
    if ct[:16] != want:
        print('FAIL: SM4 向量不符'); ok = False
    back = sm4_ecb_dec(key, ct)
    if back != pt:
        print('FAIL: SM4 往返失败'); ok = False
    # ② 多块往返
    for n in (1, 15, 16, 17, 40):
        d = bytes((i * 7 + 3) & 0xFF for i in range(n))
        if sm4_ecb_dec(key, sm4_ecb_enc(key, d)) != d:
            print('FAIL: SM4 往返失败 len=%d' % n); ok = False
    # ③ VM 生成器一致
    got = vmgen.vm_seed(vmgen.encode_program(MARKER, SALT, 16, vmgen.ROLLING_KEY)[1])
    print('VM    seed  = %s' % got.hex())
    print('pure  seed  = %s' % TRUE_SEED.hex())
    if got != TRUE_SEED:
        print('FAIL: VM 与纯函数不一致'); ok = False
    # ④ 端到端签名形状
    import hashlib
    payload = b'page=3&ts=1700000000'
    enc_ct = sm4_ecb_enc(TRUE_SEED, payload)
    sy = hashlib.md5(TRUE_SEED.hex().encode() + enc_ct.hex().encode()).hexdigest()
    print('SM4  key    = %s' % TRUE_SEED.hex())
    print('sign sample = %s' % sy)
    print('SELFTEST', 'OK' if ok else 'FAILED')
    return ok


def main():
    args = sys.argv[1:]
    ok = selftest()
    if '--selftest' in args:
        sys.exit(0 if ok else 1)
    if not ok:
        sys.exit(1)

    files = {
        'lattice.cpp': T_LATTICE,
        'basalt.cpp': T_BASALT.replace('__SBOX__', sbox_c()),
        'ingot.cpp': T_INGOT,
        'harbor.cpp': T_HARBOR,
        'beacon.cpp': T_BEACON,
    }
    for name, body in files.items():
        path = os.path.join(JNI, name)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(c_header() + body)
        print('写入 %-14s %6d B' % (name, os.path.getsize(path)))

    old = os.path.join(JNI, 'kkl3.cpp')
    if os.path.exists(old):
        os.remove(old)
        print('删除旧模块 kkl3.cpp')
    print('ALL SOURCES OK')


if __name__ == '__main__':
    main()
