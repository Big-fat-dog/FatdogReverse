# -*- coding: utf-8 -*-
"""KKL5 诛仙台：5 个 so 的生成器（VMP · 内存机 VM + 差分反馈链 + SM4-CBC/AES-CTR 复合 + MD5）。

        ┌── libspindle.so  JNI 门面（唯一暴露 Java_ 符号）；dlsym 其余四个内核
        ├── libvellum.so  虚拟机内核：差分链解密 + 内存机解释执行（16 单元 + 累加器）
        ├── libnimbus.so  SM4-CBC（内层）+ AES-128-CTR（外层）复合加解密 + 十六进制
        ├── libtallow.so  MD5 摘要（取数签名，零 HMAC）
        └── libwraith.so  完整性守卫：调试/段权限/断点/模拟器/可疑映射（阈值 2）

五者缺一：门面 dlsym 拿不到内核指针 → 自检报"内核缺失"、签名返回空 → 服务端 403。

数据链（全网络取数，`GET /api/kkl5`）：
    seed(32B) = VM( 输入 = 真标记 Fatdog_ascend ‖ "|kkl5_altar" )   ← 标记不进字节码
                sm4_key = seed[0:16]，aes_key = seed[16:32]
                sm4_iv  = md5(seed ‖ "|sm4")[:16]
    inner     = SM4-CBC(sm4_key, sm4_iv, PKCS7("page=N&ts=T"))
    enc       = hex( aes_iv ‖ AES-128-CTR(aes_key, aes_iv, inner) )，aes_iv = md5(seed ‖ "|aes")[:16]
    sign      = md5( hex(seed) + enc )
服务端：先解外层 AES-CTR，再解内层 SM4-CBC，必须还原出 "page=N&ts=T"，且 sign 对得上。

标记：真 = Fatdog_ascend（UTF-16 码元藏 .data，运行时降 ASCII 喂给 VM）
      假 = Fatdog_ascent（明文躺 .rodata，仅末位一字之差；派生的主钥服务端不认）

用法：
    python gen_kkl5.py                    # 生成 5 个 so 源 + 自测
    python gen_kkl5.py --selftest         # 只跑自测
    python gen_kkl5.py --bake <dex>       # 用复合算法把业务 dex 埋进 assets/kkl5/
"""
import hashlib
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
JNI = os.path.join(HERE, 'app', 'jni')
ASSET_DIR = os.path.join(HERE, 'app', 'assets', 'kkl5')

# ─────────────── 与 tools/gen_kkl5_vm_program.py 的共享事实（硬约束） ───────────────
MARKER = b"Fatdog_ascend"
DECOY = b"Fatdog_ascent"
SALT = b"|kkl5_altar"
PAGES, PER_PAGE, SEED = 100, 10, 20260930
DECOY_MAGIC = b"ZhuXianTai:DecoyShell"

sys.path.insert(0, os.path.join(HERE, 'tools'))
import gen_kkl5_vm_program as vmgen  # noqa: E402

assert vmgen.MARKER_REAL == MARKER and vmgen.MARKER_DECOY == DECOY and vmgen.SALT_KEY == SALT, \
    '标记/salt 与 VM 生成器不一致'
TRUE_SEED = vmgen.derive_key(MARKER, SALT, 32)

_rng = random.Random(SEED)
_NUMS = [_rng.randint(1, 100) for _ in range(PAGES * PER_PAGE)]
SUM = sum(_NUMS)
SUM_HASH = hashlib.md5(str(SUM).encode()).hexdigest()


# ─────────────────────────── 纯 Python SM4（GB/T 32907-2016） ───────────────────────────
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


# ─────────────────────────── 纯 Python AES-128（CTR 用） ───────────────────────────
AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]


def _xtime(a):
    a <<= 1
    return (a ^ 0x11b) & 0xFF if a & 0x100 else a & 0xFF


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p & 0xFF


def _expand_key(key):
    w = list(key)
    rcon = 1
    for i in range(4, 44):
        t = w[(i - 1) * 4:(i - 1) * 4 + 4]
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [AES_SBOX[x] for x in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        w += [w[(i - 4) * 4 + j] ^ t[j] for j in range(4)]
    return w


def _shift_rows(st):
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[c * 4 + r] = st[((c + r) % 4) * 4 + r]
    return out


def _mix_columns(st):
    out = [0] * 16
    m = [2, 3, 1, 1]
    for c in range(4):
        col = st[c * 4:c * 4 + 4]
        for r in range(4):
            out[c * 4 + r] = (_gmul(col[0], m[(0 - r) % 4]) ^ _gmul(col[1], m[(1 - r) % 4])
                              ^ _gmul(col[2], m[(2 - r) % 4]) ^ _gmul(col[3], m[(3 - r) % 4]))
    return out


def aes_encrypt_block(block, w):
    st = [block[i] ^ w[i] for i in range(16)]
    for rnd in range(1, 10):
        st = [AES_SBOX[x] for x in st]
        st = _shift_rows(st)
        st = _mix_columns(st)
        st = [st[i] ^ w[rnd * 16 + i] for i in range(16)]
    st = [AES_SBOX[x] for x in st]
    st = _shift_rows(st)
    return bytes(st[i] ^ w[160 + i] for i in range(16))


def aes_ctr(key, iv, data):
    w = _expand_key(key)
    base = int.from_bytes(iv[12:16], 'big')
    out = bytearray()
    for j, off in enumerate(range(0, len(data), 16)):
        ctr = iv[0:12] + ((base + j) & M32).to_bytes(4, 'big')
        ks = aes_encrypt_block(ctr, w)
        blk = data[off:off + 16]
        out += bytes(a ^ b for a, b in zip(blk, ks))
    return bytes(out)


# ─────────────────────── 复合原语（SM4-CBC 内层 + AES-CTR 外层） ───────────────────────
def _pkcs7(data, block=16):
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def sm4_cbc_enc(key, iv, data):
    pt = _pkcs7(data, 16)
    rk = sm4_keys(key)
    out = bytearray()
    prev = iv
    for off in range(0, len(pt), 16):
        blk = bytes(a ^ b for a, b in zip(pt[off:off + 16], prev))
        prev = _sm4_block(rk, blk)
        out += prev
    return bytes(out)


def sm4_cbc_dec(key, iv, data):
    rk = sm4_keys(key)[::-1]
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        c = data[off:off + 16]
        out += bytes(a ^ b for a, b in zip(_sm4_block(rk, c), prev))
        prev = c
    pad = out[-1]
    if pad == 0 or pad > 16 or out[-pad:] != bytes([pad]) * pad:
        return None
    return bytes(out[:-pad])


def _iv_sm4(seed):
    return hashlib.md5(seed + b"|sm4").digest()[:16]


def _iv_aes(seed):
    return hashlib.md5(seed + b"|aes").digest()[:16]


def composite_seal(seed, plain):
    """返回 aes_iv(16) ‖ AES-128-CTR(aes_key, aes_iv, SM4-CBC(sm4_key, sm4_iv, plain))。"""
    sm4_key, aes_key = seed[:16], seed[16:]
    inner = sm4_cbc_enc(sm4_key, _iv_sm4(seed), plain)
    aes_iv = _iv_aes(seed)
    return aes_iv + aes_ctr(aes_key, aes_iv, inner)


def composite_unseal(seed, blob):
    if len(blob) < 32 or (len(blob[16:]) % 16) != 0:
        return None
    sm4_key, aes_key = seed[:16], seed[16:]
    aes_iv, outer = blob[:16], blob[16:]
    inner = aes_ctr(aes_key, aes_iv, outer)
    return sm4_cbc_dec(sm4_key, _iv_sm4(seed), inner)


# ─────────────────────────────── C++ 模板 ───────────────────────────────
def sbox_c():
    rows = []
    for i in range(0, 256, 16):
        rows.append('    ' + ', '.join('0x%02X' % b for b in SBOX[i:i + 16]) + ',')
    return 'static const uint8_t SBOX[256] = {\n' + '\n'.join(rows) + '\n};'


def ck_c():
    vals = []
    for i in range(32):
        for j in range(4):
            vals.append(((4 * i + j) * 7) & 0xFF)
    rows = []
    for i in range(0, 128, 16):
        rows.append('    ' + ', '.join('0x%02X' % b for b in vals[i:i + 16]) + ',')
    return 'static const uint8_t CK[128] = {\n' + '\n'.join(rows) + '\n};'


def marker_jchar():
    return ', '.join('0x%04X' % c for c in MARKER)


T_SPINDLE = r'''/*
 * spindle —— 太玄之初 KKL5 诛仙台的 JNI 门面。
 *
 * 本 so 是全关**唯一**导出 Java_ 符号的库；它自身不含任何算法，
 * 全部内核靠 dlsym(RTLD_DEFAULT) 从其它四个 so 取：
 *     vl_derive      （vellum）内存机虚拟机派生主钥（32B）
 *     nm_seal/nm_unseal/nm_hex（nimbus）SM4-CBC+AES-CTR 复合与十六进制
 *     tl_tally/tl_hex（tallow）MD5 摘要
 *     wr_scan        （wraith）完整性守卫
 * 缺任一内核 → 自检报"内核缺失"，签名返回空串。
 *
 * 真标记以 UTF-16 码元藏在本文件的 .data（MK5[]），运行时逐字降 ASCII 后
 * 与 salt 拼成输入缓冲喂给虚拟机——标记**不进入字节码**，字节码里只有取数下标。
 */
#include <jni.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kkl5_vm_program.h"

typedef bool (*fn_derive)(const uint8_t *, size_t, const uint8_t *, size_t,
                          const uint8_t *, size_t, const uint8_t *, size_t,
                          uint8_t *, int);
typedef int  (*fn_seal)(const uint8_t *, const uint8_t *, const uint8_t *,
                        const uint8_t *, size_t, uint8_t *);
typedef int  (*fn_unseal)(const uint8_t *, const uint8_t *, const uint8_t *, size_t, uint8_t *);
typedef void (*fn_hex)(const uint8_t *, size_t, char *);
typedef void (*fn_tally)(const uint8_t *, size_t, uint8_t *);
typedef void (*fn_ihex)(const uint8_t *, int, char *);
typedef int  (*fn_scan)(int *);

static fn_derive g_derive = NULL;
static fn_seal   g_seal = NULL;
static fn_unseal g_unseal = NULL;
static fn_hex    g_hex = NULL;
static fn_tally  g_tally = NULL;
static fn_ihex   g_ihex = NULL;
static fn_scan   g_scan = NULL;

static volatile int g_poisoned = 0;

/* ================= 真标记：UTF-16 藏匿（const volatile 保证不被折叠成立即数） ================= */
static const volatile jchar MK5[] = { __MARKER_JCHAR__ };
#define MK5_LEN ((int)(sizeof(MK5) / sizeof(jchar)))

/* 明文诱饵：与真标记仅末位一字之差（d/t），由 kd_seal_tag() 引用，保证进 .rodata */
static const char DECOY[] = "Fatdog_ascent";
static const char SALT[]  = "|kkl5_altar";

static void bind_kernels(void) {
    if (g_derive) return;
    g_derive = (fn_derive)dlsym(RTLD_DEFAULT, "vl_derive");
    g_seal   = (fn_seal)  dlsym(RTLD_DEFAULT, "nm_seal");
    g_unseal = (fn_unseal)dlsym(RTLD_DEFAULT, "nm_unseal");
    g_hex    = (fn_hex)   dlsym(RTLD_DEFAULT, "nm_hex");
    g_tally  = (fn_tally) dlsym(RTLD_DEFAULT, "tl_tally");
    g_ihex   = (fn_ihex)  dlsym(RTLD_DEFAULT, "tl_hex");
    g_scan   = (fn_scan)  dlsym(RTLD_DEFAULT, "wr_scan");
}

static int kernel_missing(void) {
    return !(g_derive && g_seal && g_unseal && g_hex && g_tally && g_ihex && g_scan);
}

/* 拼装虚拟机输入缓冲：真标记(UTF-16 降 ASCII) ‖ salt。 */
static int build_input(uint8_t *in, int cap) {
    int p = 0;
    for (int i = 0; i < MK5_LEN && p < cap; i++) in[p++] = (uint8_t)(MK5[i] & 0xFF);
    for (const char *s = SALT; *s && p < cap; s++) in[p++] = (uint8_t)*s;
    return p;
}

static int hit_count(int bits) {
    int h = 0;
    for (int m = 1; m != 0 && m <= 16; m <<= 1) if (bits & m) h++;
    return h;
}

/* 派生主钥：跑虚拟机；命中 >= 2 项即翻位投毒（服务端恒 403）。 */
static int derive_seed(uint8_t seed[32]) {
    bind_kernels();
    if (kernel_missing()) return 0;
    int bits = 0;
    g_scan(&bits);
    uint8_t in[64];
    int in_len = build_input(in, sizeof(in));
    if (!g_derive(kKkl5VmProgram, KKL5_VM_PROGRAM_BYTES,
                  kKkl5VmStreamKey, KKL5_VM_STREAM_KEY_LEN,
                  kKkl5VmChainIV, KKL5_VM_CHAIN_IV_LEN,
                  in, in_len, seed, 32)) {
        g_poisoned = 1;
        return 0;
    }
    if (hit_count(bits) >= 2) {
        seed[7] ^= 0x40;                 /* 投毒：本地主钥与服务端不再一致 */
        g_poisoned = 1;
    }
    return 1;
}

static void iv_from_seed(const uint8_t seed[32], const char *tag, uint8_t out[16]) {
    /* md5(seed ‖ tag)[:16]；复用 tallow 的 tl_tally。 */
    uint8_t msg[64];
    int n = 32;
    memcpy(msg, seed, 32);
    for (const char *s = tag; *s; s++) msg[n++] = (uint8_t)*s;
    uint8_t dig[16];
    g_tally(msg, (size_t)n, dig);
    memcpy(out, dig, 16);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl5Native_nativeStatus(JNIEnv *env, jclass) {
    bind_kernels();
    char buf[680];
    if (kernel_missing()) {
        snprintf(buf, sizeof(buf),
                 "内核编队不完整：虚拟机 %s / 分组 %s / 摘要 %s / 守卫 %s\n"
                 "lib/ 下五个 so 缺一不可。",
                 g_derive ? "在位" : "缺失", g_seal ? "在位" : "缺失",
                 g_tally ? "在位" : "缺失", g_scan ? "在位" : "缺失");
        return env->NewStringUTF(buf);
    }
    int bits = 0;
    g_scan(&bits);
    snprintf(buf, sizeof(buf),
             "完整性自检（命中 %d 项，>=2 触发投毒）：\n"
             "  调试器痕迹 : %s\n"
             "  可写可执行段 : %s\n"
             "  断点痕迹   : %s\n"
             "  模拟器环境 : %s\n"
             "  自映射完整性 : %s\n"
             "  主钥状态   : %s\n"
             "  明文可见   : Fatdog_ascent（供比对）",
             hit_count(bits),
             (bits & 1) ? "命中" : "安全", (bits & 2) ? "命中" : "安全",
             (bits & 4) ? "命中" : "安全", (bits & 8) ? "命中" : "安全",
             (bits & 16) ? "命中" : "安全",
             g_poisoned ? "已污染（服务端将拒绝）" : "正常");
    return env->NewStringUTF(buf);
}

/* onCreate 抽取：门禁在虚拟机里跑，Java 侧只看结果。 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl5Native_nativeOnCreate(JNIEnv *env, jclass, jobject) {
    uint8_t seed[32];
    if (!derive_seed(seed)) {
        bind_kernels();
        return env->NewStringUTF(kernel_missing()
            ? "FAIL: 内核编队不完整" : "FAIL: 虚拟机未收敛");
    }
    return env->NewStringUTF("OK: onCreate 门禁通过（虚拟机已收敛）");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl5Native_nativeSign(JNIEnv *env, jclass, jint page, jlong ts) {
    uint8_t seed[32];
    if (!derive_seed(seed)) return env->NewStringUTF("");

    char payload[64];
    int pl = snprintf(payload, sizeof(payload), "page=%d&ts=%lld", (int)page, (long long)ts);

    uint8_t sm4_iv[16], aes_iv[16];
    iv_from_seed(seed, "|sm4", sm4_iv);
    iv_from_seed(seed, "|aes", aes_iv);

    uint8_t ct[256];
    int cl = g_seal(seed, sm4_iv, aes_iv, (const uint8_t *)payload, (size_t)pl, ct);
    if (cl <= 0) { g_poisoned = 1; return env->NewStringUTF(""); }
    char enc[600];
    g_hex(ct, (size_t)cl, enc);

    char kh[80];
    g_ihex(seed, 32, kh);
    char msg[700];
    snprintf(msg, sizeof(msg), "%s%s", kh, enc);
    uint8_t mac[16];
    g_tally((const uint8_t *)msg, strlen(msg), mac);
    char sign[40];
    g_ihex(mac, 16, sign);

    char out[680];
    snprintf(out, sizeof(out), "%s|%s", enc, sign);
    return env->NewStringUTF(out);
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_fatdog_reverse_Kkl5Native_nativeUnseal(JNIEnv *env, jclass, jbyteArray sealed) {
    uint8_t seed[32];
    if (!derive_seed(seed)) return NULL;
    jsize n = env->GetArrayLength(sealed);
    if (n <= 16) return NULL;
    jbyte *in = env->GetByteArrayElements(sealed, NULL);
    if (!in) return NULL;
    uint8_t sm4_iv[16];
    iv_from_seed(seed, "|sm4", sm4_iv);
    uint8_t *out = (uint8_t *)malloc((size_t)n);
    int ol = out ? g_unseal(seed, sm4_iv, (const uint8_t *)in, (size_t)n, out) : -1;
    env->ReleaseByteArrayElements(sealed, in, JNI_ABORT);
    if (ol <= 0) { free(out); return NULL; }
    jbyteArray res = env->NewByteArray(ol);
    if (res) env->SetByteArrayRegion(res, 0, ol, (const jbyte *)out);
    free(out);
    return res;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Kkl5Native_nativePoisoned(JNIEnv *env, jclass) {
    (void)env;
    return g_poisoned ? 1 : 0;
}

/* 诱饵标记的出入口：保证 DECOY 进 .rodata，同时给静态分析留一条"假线索"。 */
extern "C" __attribute__((visibility("default"))) const char *kd_seal_tag(void) {
    return DECOY;
}
'''

T_VELLUM = r'''/*
 * vellum —— 太玄之初 KKL5 诛仙台的内存机内核。
 *
 * 只做一件事：把**差分反馈链**加密的自定义字节码逐条解密后，用内存机解释器执行，
 * 把结果内存单元回吐给上层。真标记不在本文件、也不在字节码里——程序只含 `GETM idx`，
 * 标记字节由门面在运行时从 .data 的 UTF-16 数组喂入。
 *
 * 指令编码： word = (op << 24) | (d << 20) | (s << 16) | imm16
 * 差分链：   dec[n] = enc[n] ^ key[n % L] ^ enc[n-1]；enc[-1] = IV
 *            （密文自反馈：每一条解密都依赖上一条密文，无法整段独立解）
 * 架构：     16 个内存单元 M[0..15] + 一个累加器 acc；输出单元 M8..M15 小端拼 32 字节。
 * 由 tools/gen_kkl5_vm_program.py 生成对应字节码，二者必须同步修改。
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define VL_VIS __attribute__((visibility("default")))

enum {
    VL_SET  = 0x01, VL_SETH = 0x02, VL_CPY  = 0x03, VL_GETA = 0x04,
    VL_PUTA = 0x05, VL_GETM = 0x06, VL_ADDI = 0x07, VL_MULK = 0x08,
    VL_XORR = 0x09, VL_ANDR = 0x0A, VL_ORR  = 0x0B, VL_ADDR = 0x0C,
    VL_SUBR = 0x0D, VL_SHL  = 0x0E, VL_SHR  = 0x0F, VL_ROL8 = 0x10,
    VL_ROR8 = 0x11, VL_XORI = 0x12, VL_ANDI = 0x13, VL_JMP  = 0x14,
    VL_JZ   = 0x15, VL_JNZ  = 0x16, VL_HALT = 0x17
};

#define VL_MCELLS 16
#define VL_STEPS  400000

/*
 * 解释执行。program 为差分链密文（小端 32 位词），key/iv 为链密钥流与初值，
 * in/in_len 为运行时输入缓冲（GETM 从中取字节）。
 * 返回 true 表示正常 HALT；输出单元小端拼出 out（out_len 字节）。
 */
extern "C" VL_VIS bool vl_derive(const uint8_t *program, size_t prog_len,
                                 const uint8_t *key, size_t key_len,
                                 const uint8_t *iv, size_t iv_len,
                                 const uint8_t *in, size_t in_len,
                                 uint8_t *out, int out_len) {
    if (!program || !out || out_len <= 0) return false;
    if (!key || key_len == 0 || !iv || iv_len < 4) return false;
    size_t n = prog_len / 4;
    if (n == 0) return false;

    uint32_t *words = (uint32_t *)calloc(n, sizeof(uint32_t));
    if (!words) return false;

    uint32_t prev = (uint32_t)iv[0] | ((uint32_t)iv[1] << 8)
                  | ((uint32_t)iv[2] << 16) | ((uint32_t)iv[3] << 24);
    for (size_t i = 0; i < n; i++) {
        uint32_t e = (uint32_t)program[i * 4] | ((uint32_t)program[i * 4 + 1] << 8)
                   | ((uint32_t)program[i * 4 + 2] << 16) | ((uint32_t)program[i * 4 + 3] << 24);
        uint32_t d = e ^ (uint32_t)key[i % key_len] ^ prev;
        words[i] = d;
        prev = e;                                  /* 密文自反馈 */
    }

    uint32_t M[VL_MCELLS];
    memset(M, 0, sizeof(M));
    uint32_t acc = 0;
    int pc = 0, steps = 0;
    bool halted = false;
    while (pc >= 0 && (size_t)pc < n && steps < VL_STEPS) {
        uint32_t w = words[pc];
        uint32_t op = (w >> 24) & 0xFFu;
        uint32_t d = (w >> 20) & 0xFu;
        uint32_t s = (w >> 16) & 0xFu;
        uint32_t imm = w & 0xFFFFu;
        steps++;
        bool jumped = false;
        switch (op) {
        case VL_SET:  M[d] = imm; break;
        case VL_SETH: M[d] = (M[d] & 0x0000FFFFu) | (imm << 16); break;
        case VL_CPY:  M[d] = M[s]; break;
        case VL_GETA: acc = M[d]; break;
        case VL_PUTA: M[d] = acc; break;
        case VL_GETM: acc = (in && imm < in_len) ? in[imm] : 0u; break;
        case VL_ADDI: acc = acc + imm; break;
        case VL_MULK: acc = acc * imm; break;
        case VL_XORR: acc = acc ^ M[s]; break;
        case VL_ANDR: acc = acc & M[s]; break;
        case VL_ORR:  acc = acc | M[s]; break;
        case VL_ADDR: acc = acc + M[s]; break;
        case VL_SUBR: acc = acc - M[s]; break;
        case VL_SHL:  acc = acc << (imm & 0x1Fu); break;
        case VL_SHR:  acc = acc >> (imm & 0x1Fu); break;
        case VL_ROL8: {
            uint32_t v = acc & 0xFFu, r = imm & 7u;
            acc = ((v << r) | (v >> (8 - r))) & 0xFFu;
        } break;
        case VL_ROR8: {
            uint32_t v = acc & 0xFFu, r = imm & 7u;
            acc = ((v >> r) | (v << (8 - r))) & 0xFFu;
        } break;
        case VL_XORI: acc = acc ^ imm; break;
        case VL_ANDI: acc = acc & imm; break;
        case VL_JMP:  pc = (int)imm; jumped = true; break;
        case VL_JZ:   if (acc == 0) { pc = (int)imm; jumped = true; } break;
        case VL_JNZ:  if (acc != 0) { pc = (int)imm; jumped = true; } break;
        case VL_HALT: halted = true; break;
        default: free(words); return false;
        }
        if (halted) break;
        if (!jumped) pc++;
    }
    bool ok = halted;
    if (ok) {
        for (int i = 0; i < out_len; i++)
            out[i] = (uint8_t)((M[8 + i / 4] >> (8 * (i % 4))) & 0xFFu);
    }
    free(words);
    return ok;
}

/* 诱饵：另一组形状相同、值不同的"主钥"（服务端不认）。 */
extern "C" VL_VIS void vl_decoy_head(uint8_t *out, int n) {
    for (int i = 0; i < n && i < 32; i++) out[i] = (uint8_t)(0x27 ^ (i * 0x1B));
}
'''

T_NIMBUS = r'''/*
 * nimbus —— 太玄之初 KKL5 诛仙台的复合原语内核。
 *
 * 内层 **SM4-CBC**（国密分组，128 位密钥 / 128 位分组，32 轮）+ PKCS#7；
 * 外层 **AES-128-CTR**（计数器块 = iv[0:12] ‖ (iv[12:16] + 块号) 大端）。
 * 两个 S 盒分别按 GB/T 32907-2016 与 FIPS-197 硬编码，轮常量现算。
 *
 * 复合口径（与 gen_kkl5.py / server.py 逐字节对齐）：
 *     sm4_key = seed[0:16]；aes_key = seed[16:32]
 *     enc     = aes_iv(16) ‖ AES-CTR(aes_key, aes_iv, SM4-CBC(sm4_key, sm4_iv, plain))
 * 其中 sm4_iv 由门面从 seed 派生后传入；aes_iv 由门面派生并随密文前 16 字节携带。
 */
#include <stdint.h>
#include <string.h>

#define NM_VIS __attribute__((visibility("default")))

__SM4SBOX__
static const uint32_t FK[4] = {0xa3b1bac6u, 0x56aa3350u, 0x677d9197u, 0xb27022dcu};
__CK__

/* ---------------- SM4 ---------------- */
static uint32_t nm_rot(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static uint32_t nm_tau(uint32_t x) {
    return ((uint32_t)SBOX[(x >> 24) & 0xFF] << 24) | ((uint32_t)SBOX[(x >> 16) & 0xFF] << 16)
         | ((uint32_t)SBOX[(x >> 8) & 0xFF] << 8)  | (uint32_t)SBOX[x & 0xFF];
}
static uint32_t nm_t(uint32_t x) {
    uint32_t b = nm_tau(x);
    return b ^ nm_rot(b, 2) ^ nm_rot(b, 10) ^ nm_rot(b, 18) ^ nm_rot(b, 24);
}
static uint32_t nm_tp(uint32_t x) {
    uint32_t b = nm_tau(x);
    return b ^ nm_rot(b, 13) ^ nm_rot(b, 23);
}
static uint32_t nm_ck(int i) {
    const uint8_t *p = CK + i * 4;
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static void nm_keys(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t k[4];
    for (int i = 0; i < 4; i++) {
        k[i] = ((uint32_t)key[i * 4] << 24) | ((uint32_t)key[i * 4 + 1] << 16)
             | ((uint32_t)key[i * 4 + 2] << 8) | (uint32_t)key[i * 4 + 3];
        k[i] ^= FK[i];
    }
    for (int i = 0; i < 32; i++) {
        uint32_t nk = k[0] ^ nm_tp(k[1] ^ k[2] ^ k[3] ^ nm_ck(i));
        rk[i] = nk;
        k[0] = k[1]; k[1] = k[2]; k[2] = k[3]; k[3] = nk;
    }
}
static void nm_block(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16]) {
    uint32_t x[4];
    for (int i = 0; i < 4; i++)
        x[i] = ((uint32_t)in[i * 4] << 24) | ((uint32_t)in[i * 4 + 1] << 16)
             | ((uint32_t)in[i * 4 + 2] << 8) | (uint32_t)in[i * 4 + 3];
    for (int i = 0; i < 32; i++) {
        uint32_t nx = x[0] ^ nm_t(x[1] ^ x[2] ^ x[3] ^ rk[i]);
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

/* ---------------- AES-128（仅加密块，供 CTR 用） ---------------- */
static const uint8_t ASBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static uint8_t nm_xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }
static uint8_t nm_gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) { if (b & 1) p ^= a; a = nm_xtime(a); b >>= 1; }
    return p;
}
static void nm_aes_expand(const uint8_t key[16], uint8_t rk[176]) {
    for (int i = 0; i < 16; i++) rk[i] = key[i];
    uint8_t rcon = 1;
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];
        for (int j = 0; j < 4; j++) t[j] = rk[(i - 1) * 4 + j];
        if (i % 4 == 0) {
            uint8_t tmp = t[0]; t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = tmp;
            for (int j = 0; j < 4; j++) t[j] = ASBOX[t[j]];
            t[0] ^= rcon;
            rcon = nm_xtime(rcon);
        }
        for (int j = 0; j < 4; j++) rk[i * 4 + j] = rk[(i - 4) * 4 + j] ^ t[j];
    }
}
static void nm_aes_block(const uint8_t in[16], const uint8_t rk[176], uint8_t out[16]) {
    uint8_t s[16];
    memcpy(s, in, 16);
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];
    for (int r = 1; r < 10; r++) {
        for (int i = 0; i < 16; i++) s[i] = ASBOX[s[i]];
        uint8_t t;
        t = s[1];  s[1]  = s[5];  s[5]  = s[9];  s[9]  = s[13]; s[13] = t;
        t = s[2];  s[2]  = s[10]; s[10] = t;     t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7];  s[7]  = s[3];  s[3]  = t;
        for (int c = 0; c < 4; c++) {
            int i = c * 4;
            uint8_t a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
            s[i]     = (uint8_t)(nm_gmul(a0, 2) ^ nm_gmul(a1, 3) ^ a2 ^ a3);
            s[i + 1] = (uint8_t)(a0 ^ nm_gmul(a1, 2) ^ nm_gmul(a2, 3) ^ a3);
            s[i + 2] = (uint8_t)(a0 ^ a1 ^ nm_gmul(a2, 2) ^ nm_gmul(a3, 3));
            s[i + 3] = (uint8_t)(nm_gmul(a0, 3) ^ a1 ^ a2 ^ nm_gmul(a3, 2));
        }
        for (int i = 0; i < 16; i++) s[i] ^= rk[r * 16 + i];
    }
    for (int i = 0; i < 16; i++) s[i] = ASBOX[s[i]];
    uint8_t t;
    t = s[1];  s[1]  = s[5];  s[5]  = s[9];  s[9]  = s[13]; s[13] = t;
    t = s[2];  s[2]  = s[10]; s[10] = t;     t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7];  s[7]  = s[3];  s[3]  = t;
    for (int i = 0; i < 16; i++) out[i] = s[i] ^ rk[160 + i];
}
static void nm_aes_ctr(const uint8_t key[16], const uint8_t iv[16],
                       const uint8_t *in, size_t len, uint8_t *out) {
    uint8_t rk[176];
    nm_aes_expand(key, rk);
    uint32_t base = ((uint32_t)iv[12] << 24) | ((uint32_t)iv[13] << 16)
                  | ((uint32_t)iv[14] << 8) | (uint32_t)iv[15];
    for (size_t off = 0; off < len; off += 16) {
        uint8_t ctr[16], ks[16];
        memcpy(ctr, iv, 12);
        uint32_t c = base + (uint32_t)(off / 16);
        ctr[12] = (uint8_t)(c >> 24); ctr[13] = (uint8_t)(c >> 16);
        ctr[14] = (uint8_t)(c >> 8);  ctr[15] = (uint8_t)c;
        nm_aes_block(ctr, rk, ks);
        size_t m = (len - off < 16) ? (len - off) : 16;
        for (size_t i = 0; i < m; i++) out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
    }
}

/* ---------------- 复合封装 ---------------- */
/* 返回 16 + 密文长度；失败 0。 */
extern "C" NM_VIS int nm_seal(const uint8_t seed[32], const uint8_t sm4_iv[16],
                              const uint8_t aes_iv[16], const uint8_t *in, size_t len,
                              uint8_t *out) {
    if (!seed || !sm4_iv || !aes_iv || !in || !out) return 0;
    uint32_t rk[32];
    nm_keys(seed, rk);
    size_t pad = 16 - (len % 16);
    size_t total = len + pad;
    if (total > 240) return 0;
    uint8_t inner[240];
    uint8_t prev[16];
    memcpy(prev, sm4_iv, 16);
    for (size_t off = 0; off < total; off += 16) {
        uint8_t blk[16];
        for (int i = 0; i < 16; i++) {
            size_t p = off + i;
            blk[i] = (uint8_t)((p < len ? in[p] : (uint8_t)pad) ^ prev[i]);
        }
        nm_block(rk, blk, inner + off);
        memcpy(prev, inner + off, 16);
    }
    memcpy(out, aes_iv, 16);
    nm_aes_ctr(seed + 16, aes_iv, inner, total, out + 16);
    return (int)(16 + total);
}

/* 返回明文长度；失败 -1。 */
extern "C" NM_VIS int nm_unseal(const uint8_t seed[32], const uint8_t sm4_iv[16],
                                const uint8_t *blob, size_t len, uint8_t *out) {
    if (!seed || !sm4_iv || !blob || !out) return -1;
    if (len < 32 || ((len - 16) % 16) != 0) return -1;
    size_t total = len - 16;
    uint8_t inner[240];
    nm_aes_ctr(seed + 16, blob, blob + 16, total, inner);   /* 外层 AES-CTR 解密 */

    uint32_t rk[32], rkrev[32];
    nm_keys(seed, rk);
    for (int i = 0; i < 32; i++) rkrev[i] = rk[31 - i];
    uint8_t prev[16];
    memcpy(prev, sm4_iv, 16);
    for (size_t off = 0; off < total; off += 16) {
        uint8_t dec[16];
        nm_block(rkrev, inner + off, dec);                  /* 内层 SM4 解密 */
        for (int i = 0; i < 16; i++) out[off + i] = (uint8_t)(dec[i] ^ prev[i]);
        memcpy(prev, inner + off, 16);
    }
    uint8_t pad = out[total - 1];
    if (pad == 0 || pad > 16) return -1;
    for (size_t i = total - pad; i < total; i++) if (out[i] != pad) return -1;
    return (int)(total - pad);
}

extern "C" NM_VIS void nm_hex(const uint8_t *in, size_t len, char *out) {
    const char *t = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = t[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = t[in[i] & 0xF];
    }
    out[len * 2] = '\0';
}
'''

T_TALLOW = r'''/*
 * tallow —— 太玄之初 KKL5 诛仙台的摘要内核（MD5，零 HMAC）。
 *
 * 取数签名 = md5( hex(主钥) + 密文十六进制 )，由上层拼好后交给 tl_tally。
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TL_VIS __attribute__((visibility("default")))

static const uint32_t TL_K[64] = {
    0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
    0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
    0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
    0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
    0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
    0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
    0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
    0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u
};
#define TL_RL(x,c) (((x) << (c)) | ((x) >> (32 - (c))))

extern "C" TL_VIS void tl_tally(const uint8_t *msg, size_t len, uint8_t out[16]) {
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
            b = b + TL_RL(a + f + TL_K[i] + m[g], S[i]);
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

extern "C" TL_VIS void tl_hex(const uint8_t *in, int n, char *out) {
    const char *t = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[i * 2] = t[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = t[in[i] & 0xF];
    }
    out[n * 2] = '\0';
}
'''

T_WRAITH = r'''/*
 * wraith —— 太玄之初 KKL5 诛仙台的完整性守卫（评分阈值制）。
 *
 * 五路（全部只查"有没有人动过我的代码/运行环境"，**不内置任何第三方注入框架检测**，
 * 对齐太玄之初的守卫白名单 G1/G3/G4/G5，避免与扶桑树分区撞题）：
 *   ① 调试器痕迹  /proc/self/status:TracerPid
 *   ② 段权限审计  自身映射里出现可写+可执行的段
 *   ③ 断点痕迹    本函数首 4 字节是否为 BRK / INT3 编码
 *   ④ 环境检测    ro.kernel.qemu 等模拟器特征
 *   ⑤ 自映射完整性 自身 so 的可执行段被标记 `(deleted)`（文件被替换/删除后仍在内存执行）
 *
 * 返回命中位掩码；上层按"命中数 >= 2"判风险，命中即静默投毒（签名主钥翻位）。
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/system_properties.h>

#define WR_VIS __attribute__((visibility("default")))

#define HIT_TRACE   1
#define HIT_SECTION 2
#define HIT_BREAK   4
#define HIT_EMU     8
#define HIT_SELF    16

static int wr_tracer(void) {
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

static int wr_section(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    int hit = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "rwx")) { hit = 1; break; }
    }
    fclose(f);
    return hit;
}

static int wr_break(void) {
    uint32_t head = 0;
    memcpy(&head, (const void *)(uintptr_t)&wr_break, 4);
    if (head == 0xD4200000u) return 1;                            /* BRK #0（AArch64） */
    if (head == 0xCCCCCCCCu || (head & 0xFF) == 0xCC) return 1;   /* INT3（x86 兼容） */
    return 0;
}

static int wr_selfmap(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    static const char *own[] = {
        "libspindle.so", "libvellum.so", "libnimbus.so",
        "libtallow.so", "libwraith.so", 0
    };
    char line[512];
    int hit = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, " r-x") && !strstr(line, "rwx")) continue;
        if (!strstr(line, " (deleted)")) continue;
        for (int i = 0; own[i]; i++) {
            if (strstr(line, own[i])) { hit = 1; break; }
        }
        if (hit) break;
    }
    fclose(f);
    return hit;
}

static int wr_emulator(void) {
    char v[128];
    if (__system_property_get("ro.kernel.qemu", v) > 0 && v[0] == '1') return 1;
    if (__system_property_get("init.svc.qemud", v) > 0 && strcmp(v, "running") == 0) return 1;
    if (__system_property_get("ro.build.characteristics", v) > 0 && strstr(v, "emulator")) return 1;
    return 0;
}

extern "C" WR_VIS int wr_scan(int *detail) {
    int bits = 0;
    if (wr_tracer())   bits |= HIT_TRACE;
    if (wr_section())  bits |= HIT_SECTION;
    if (wr_break())    bits |= HIT_BREAK;
    if (wr_emulator()) bits |= HIT_EMU;
    if (wr_selfmap())  bits |= HIT_SELF;
    if (detail) *detail = bits;
    return bits;
}
'''


def c_header():
    return ('/* 自动生成：python gen_kkl5.py —— 请勿手改。 */\n'
            '/* 太玄之初 KKL5 诛仙台 · 五 so 编队（门面/虚拟机/复合分组/摘要/守卫）。 */\n\n')


# ─────────────────────────── bake（业务 DEX） ───────────────────────────
def bake(dex_path):
    with open(dex_path, 'rb') as f:
        plain = f.read()
    os.makedirs(ASSET_DIR, exist_ok=True)
    sealed = composite_seal(TRUE_SEED, plain)
    out = os.path.join(ASSET_DIR, 'ascension_altar.bin')
    with open(out, 'wb') as f:
        f.write(sealed)
    decoy = os.path.join(ASSET_DIR, 'classes_decoy.dex')
    with open(decoy, 'wb') as f:
        f.write(DECOY_MAGIC + b"\n" + bytes((i * 7 + 3) & 0xFF for i in range(1024)))
    print("KKL5 seal: %s (%d -> %d bytes)" % (out, len(plain), len(sealed)))
    print("KKL5 decoy: %s" % decoy)


def selftest():
    ok = True
    # ① SM4 标准向量（GB/T 32907-2016 附录 A）：key==plaintext
    key = bytes.fromhex('0123456789abcdeffedcba9876543210')
    rk = sm4_keys(key)
    ct = _sm4_block(rk, key)
    print('SM4    block  = %s' % ct.hex())
    print('SM4    expect = 681edf34d206965e86b3e94f536e4246')
    if ct != bytes.fromhex('681edf34d206965e86b3e94f536e4246'):
        print('FAIL: SM4 向量不符'); ok = False
    # ② AES-128 FIPS-197 附录 B 向量
    w = _expand_key(bytes(range(16)))
    ct = aes_encrypt_block(bytes.fromhex('00112233445566778899aabbccddeeff'), w)
    if ct != bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a'):
        print('FAIL: AES 向量不符'); ok = False
    # ③ 复合往返 + 多长度
    for n in (1, 15, 16, 17, 40, 96):
        d = bytes((i * 13 + 7) & 0xFF for i in range(n))
        blob = composite_seal(TRUE_SEED, d)
        if composite_unseal(TRUE_SEED, blob) != d:
            print('FAIL: 复合往返失败 len=%d' % n); ok = False
    # ④ VM 生成器一致
    _, enc_words, _ = vmgen.encode_program(len(MARKER), len(SALT), 32)
    got = vmgen.vm_seed(enc_words, vmgen.build_input(MARKER, SALT), 32)
    print('VM     seed = %s' % (got.hex() if got else 'None'))
    print('pure   seed = %s' % TRUE_SEED.hex())
    if got != TRUE_SEED:
        print('FAIL: VM 与纯函数不一致'); ok = False
    # ⑤ 端到端：请求帧复合往返
    payload = b'page=7&ts=1700000000'
    blob = composite_seal(TRUE_SEED, payload)
    enc = blob.hex()
    sign = hashlib.md5(TRUE_SEED.hex().encode() + enc.encode()).hexdigest()
    if composite_unseal(TRUE_SEED, blob) != payload:
        print('FAIL: 端到端解密回环失败'); ok = False
    print('enc sample = %s' % enc)
    print('sign sample= %s' % sign)
    # ⑥ MD5 已知向量
    if hashlib.md5(b'abc').hexdigest() != '900150983cd24fb0d6963f7d28e17f72':
        print('FAIL: hashlib MD5 异常'); ok = False
    print('SUM        = %d' % SUM)
    print('SUM_HASH   = %s' % SUM_HASH)
    print('SEED_HEX   = %s' % TRUE_SEED.hex())
    print('SELFTEST', 'OK' if ok else 'FAILED')
    return ok


def main():
    args = sys.argv[1:]
    if '--bake' in args:
        bake(args[args.index('--bake') + 1])
        return
    ok = selftest()
    if '--selftest' in args:
        sys.exit(0 if ok else 1)
    if not ok:
        sys.exit(1)

    files = {
        'spindle.cpp': T_SPINDLE.replace('__MARKER_JCHAR__', marker_jchar()),
        'vellum.cpp': T_VELLUM,
        'nimbus.cpp': T_NIMBUS.replace('__SM4SBOX__', sbox_c()).replace('__CK__', ck_c()),
        'tallow.cpp': T_TALLOW,
        'wraith.cpp': T_WRAITH,
    }
    for name, body in files.items():
        path = os.path.join(JNI, name)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(c_header() + body)
        print('写入 %-14s %6d B' % (name, os.path.getsize(path)))

    for old in ('kkl5.cpp',):
        p = os.path.join(JNI, old)
        if os.path.exists(p):
            os.remove(p)
            print('删除旧模块', old)
    print('ALL SOURCES OK')


if __name__ == '__main__':
    main()
