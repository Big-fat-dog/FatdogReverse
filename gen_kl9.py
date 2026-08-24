#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_kl9.py —— 「天罡北斗」so 生成器（魔改 RC4 · KSA 初始置换换血 + PRGA 输出过掩码）

产出 app/jni/m4.c（libm4.so）：
  - 手写 RC4 双层魔改：
      * 魔改点一：KSA 的初始 S 盒不是恒等置换 S[i]=i，而是自定义 256 字节
        置换表（由 sha256("Fatdog_veil|ksa") 经确定性 Fisher-Yates 派生，可复算）；
      * 魔改点二：PRGA 每字节输出后再异或一层 16 字节循环掩码
        （sha256("Fatdog_veil|mask")[:16]）。
    标准 RC4 解不出本关密文。
  - 密钥运行时派生：rc4_key = sha256(<标记>|"rc4")[:16]，mac = sha256(<标记>|"mac")；
    真标记 Fatdog_veil 以 UTF-16 码元非 static 非 const 全局藏匿（strings 盲区）。
  - 明文诱饵标记 Fatdog_vile（veil 一字之差，用它派生钥的请求一律 403）
    + DECOY_BLOB（诱饵钥加密的"像样"假载荷）。
  - 导出面克制低调：JNI 两个真入口 + m4_decoy_seal + 两个噪声函数。

自测：
  1) 标准路径（恒等初排、无掩码）过公开向量：
     key="Secret"、明文 "Attack at dawn" -> 45a01f645fc35b383552544b9bf5；
  2) KSA_INIT 是 0..255 的排列；
  3) 魔改路径加解密回环一致，且与标准 RC4 输出不同；
  4) HMAC 与标准库一致（直接使用 hmac 库计算样例）。

用法：python gen_kl9.py   （在项目根目录执行）
"""

import hashlib
import hmac as py_hmac
import sys

M32 = 0xFFFFFFFF


def make_ksa_init(marker):
    """确定性 Fisher-Yates：以 sha256(marker|ksa) 为随机源派生 256 字节置换"""
    seed = hashlib.sha256(marker + b"|ksa").digest()
    data = b""
    ctr = 0
    while len(data) < 512:
        data += hashlib.sha256(seed + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    p = list(range(256))
    for i in range(255, 0, -1):
        r = int.from_bytes(data[(255 - i) * 2:(255 - i) * 2 + 2], "big")
        j = r % (i + 1)
        p[i], p[j] = p[j], p[i]
    return p


def rc4_crypt(init_perm, mask, key, data):
    """init_perm=None 表示恒等初排；mask=None 表示无输出掩码（即标准 RC4）"""
    s = list(range(256)) if init_perm is None else list(init_perm)
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for n, ch in enumerate(data):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        c = ch ^ k
        if mask is not None:
            c ^= mask[n % len(mask)]
        out.append(c)
    return bytes(out)


# ---------------- 自测 ----------------

def self_test():
    ok = True

    # 1) 标准路径过公开向量
    got = rc4_crypt(None, None, b"Secret", b"Attack at dawn").hex()
    want = "45a01f645fc35b383552544b9bf5"
    print("[selftest] std rc4 vector:", got)
    if got != want:
        print("[selftest] FAIL standard vector")
        ok = False

    # 2) KSA_INIT 排列校验
    marker = b"Fatdog_veil"
    init = make_ksa_init(marker)
    if sorted(init) != list(range(256)):
        print("[selftest] FAIL ksa init not permutation")
        ok = False
    ident_hits = sum(1 for i, v in enumerate(init) if i == v)
    print("[selftest] ksa init permutation ok (identity hits=%d/256)" % ident_hits)

    # 3) 魔改回环 + 与标准差异
    key = hashlib.sha256(marker + b"|rc4").digest()[:16]
    mask = hashlib.sha256(marker + b"|mask").digest()[:16]
    pt = pad(b"page=1&ts=1787013761")
    c_mod = rc4_crypt(init, mask, key, pt)
    c_std = rc4_crypt(None, None, key, pt)
    back = rc4_crypt(init, mask, key, c_mod)
    print("[selftest] modified roundtrip :", back == pt)
    if back != pt:
        print("[selftest] FAIL modified roundtrip")
        ok = False
    if c_mod == c_std:
        print("[selftest] FAIL modified identical to standard")
        ok = False
    print("[selftest] mod vs std differ  :", c_mod[:8].hex(), "!=", c_std[:8].hex())

    if not ok:
        sys.exit("self-test FAILED, refuse to emit C")


def pad(b):
    n = (len(b) + 15) // 16 * 16
    return b + b"\x00" * (n - len(b))


# ---------------- 关卡素材 ----------------

MARKER = "Fatdog_veil"                  # 真标记（UTF-16 藏匿）
DECOY_MARKER = "Fatdog_vile"            # 明文诱饵标记（veil 一字之差）
DECOY_PAYLOAD = "page=13&ts=1700000000"

RC4_KEY = hashlib.sha256(MARKER.encode() + b"|rc4").digest()[:16]
MAC_KEY = hashlib.sha256(MARKER.encode() + b"|mac").digest()
MASK = hashlib.sha256(MARKER.encode() + b"|mask").digest()[:16]
KSA_INIT = make_ksa_init(MARKER.encode())
DECOY_KEY = hashlib.sha256(DECOY_MARKER.encode() + b"|rc4").digest()[:16]

DECOY_BLOB = rc4_crypt(KSA_INIT, MASK, DECOY_KEY, pad(DECOY_PAYLOAD.encode()))


def core_enc(page, ts):
    return rc4_crypt(KSA_INIT, MASK, RC4_KEY, pad(f"page={page}&ts={ts}".encode()))


def core_sign(enc_hex):
    return py_hmac.new(MAC_KEY, enc_hex.encode(), hashlib.sha256).hexdigest()


# ---------------- C 代码生成 ----------------

def fmt_bytes(data, perline=12, indent="        "):
    rows = []
    for i in range(0, len(data), perline):
        chunk = data[i:i + perline]
        rows.append(indent + ",".join("0x%02x" % v for v in chunk) + ",")
    return "\n".join(rows)


def fmt_units(units, perline=8, indent="        "):
    rows = []
    for i in range(0, len(units), perline):
        chunk = units[i:i + perline]
        rows.append(indent + ", ".join("0x%04x" % u for u in chunk) + ",")
    return "\n".join(rows)


C_TEMPLATE = r"""/* libm4.so ——「天罡北斗」（由 gen_kl9.py 生成，勿手改）
 * 手写 RC4，两层魔改：
 *   魔改点一：KSA 的初始 S 盒不是恒等置换 S[i]=i，而是下面的自定义置换表
 *             KSA_INIT（由标记经确定性 Fisher-Yates 派生）——
 *             IDA 里看 KSA 循环前的初始化：不是清零递增而是查表加载。
 *   魔改点二：PRGA 每字节输出后再异或 16 字节循环掩码 XMASK。
 * 因此标准 RC4 解不开本关密文。
 *
 * 密钥全部运行时派生：
 *   rc4_key = sha256(<标记>|"rc4") 前 16 字节
 *   mac     = sha256(<标记>|"mac") 全 32 字节
 * 真标记存成 UTF-16 码元数组（非 static 非 const 全局），默认 strings 不显示；
 * 另有一个明文诱饵标记与一段假密文等着粗心的猎物。
 */
#include <string.h>
#include <stdio.h>

#ifndef M4_HOST_TEST
#include <jni.h>
#endif

/* 自定义初始置换（0..255 的排列；恒等命中极少——对照标准一眼可辨） */
static const unsigned char KSA_INIT[256] = {
@KSAINIT@
};

/* PRGA 输出的循环 XOR 掩码（16 字节） */
static const unsigned char XMASK[16] = {
@XMASK@
};

/* 真标记 UTF-16 码元：非 static 非 const 全局，防止编译器常量折叠进指令流 */
unsigned short MARK[@MARKLEN@] = {
@MARKER@
};

/* 明文诱饵标记：非 static 保证落盘，strings 一眼可见，一字之差 */
const char DECOY_MARK[] = "@DECOY@";

/* 假密文：用诱饵标记派生的钥加密的一段“像样”假载荷 */
static const unsigned char DECOY_BLOB[32] = {
@DBLOB@
};

/* ---------- SHA-256 / HMAC-SHA256（紧凑实现，供派生/签名复用） ---------- */

static const unsigned int K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static unsigned int m4_rotr(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }

static void m4_sha_block(unsigned int h[8], const unsigned char p[64]) {
    unsigned int w[64];
    unsigned int a,b,c,d,e,f,g,hh,t1,t2,S0,S1,mj;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[4*i]<<24)|((unsigned int)p[4*i+1]<<16)
             | ((unsigned int)p[4*i+2]<<8)|(unsigned int)p[4*i+3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = m4_rotr(w[i-15],7) ^ m4_rotr(w[i-15],18) ^ (w[i-15]>>3);
        unsigned int s1 = m4_rotr(w[i-2],17) ^ m4_rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        S1 = m4_rotr(e,6)^m4_rotr(e,11)^m4_rotr(e,25);
        t1 = hh + S1 + ((e&f)^((~e)&g)) + K256[i] + w[i];
        S0 = m4_rotr(a,2)^m4_rotr(a,13)^m4_rotr(a,22);
        mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

static void m4_sha256(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned int h[8];
    unsigned int off, rem, tlen, i;
    unsigned char tail[128];
    unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
    h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
    for (off = 0; off + 64 <= len; off += 64)
        m4_sha_block(h, msg + off);
    rem = len - off;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++)
        tail[tlen - 1 - i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    m4_sha_block(h, tail);
    if (tlen == 128) m4_sha_block(h, tail + 64);
    for (i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(h[i]>>24);
        out[4*i+1] = (unsigned char)(h[i]>>16);
        out[4*i+2] = (unsigned char)(h[i]>>8);
        out[4*i+3] = (unsigned char)(h[i]);
    }
}

static void m4_hmac_sha256(const unsigned char *key, unsigned int klen,
                           const unsigned char *msg, unsigned int mlen,
                           unsigned char out[32]) {
    unsigned char k0[64], ipad[64], opad[64], ih[32], buf[192];
    unsigned int i;
    memset(k0, 0, sizeof(k0));
    if (klen > 64) m4_sha256(key, klen, k0);
    else memcpy(k0, key, klen);
    for (i = 0; i < 64; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    if (mlen > 120) mlen = 120;
    memcpy(buf, ipad, 64);
    memcpy(buf + 64, msg, mlen);
    m4_sha256(buf, 64 + mlen, ih);
    memcpy(buf, opad, 64);
    memcpy(buf + 64, ih, 32);
    m4_sha256(buf, 96, out);
}

/* ---------- 魔改 RC4 核心（加密解密同一函数：流异或自反） ---------- */

static void m4_rc4(const unsigned char *key, int klen, unsigned char *buf, int len) {
    unsigned char S[256];
    int i, j, n, t;
    memcpy(S, KSA_INIT, 256);
    j = 0;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % klen]) & 0xFF;
        t = S[i]; S[i] = S[j]; S[j] = (unsigned char)t;
    }
    i = 0; j = 0;
    for (n = 0; n < len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        t = S[i]; S[i] = S[j]; S[j] = (unsigned char)t;
        buf[n] ^= S[(S[i] + S[j]) & 0xFF] ^ XMASK[n & 15];
    }
}

/* 标记运行时拼装 + 派生：suffix 形如 "|rc4"/"|mask"/"|mac" */
static void m4_derive(const char *suffix, unsigned char *out, int outlen) {
    char mk[32];
    char msg[48];
    unsigned char dg[32];
    int i, n = sizeof(MARK) / sizeof(unsigned short);
    int slen = (int)strlen(suffix);
    for (i = 0; i < n; i++) mk[i] = (char)(MARK[i] & 0xFF);
    mk[n] = 0;
    memcpy(msg, mk, (size_t)n);
    memcpy(msg + n, suffix, (size_t)slen);
    m4_sha256((const unsigned char *)msg, (unsigned int)(n + slen), dg);
    memcpy(out, dg, (size_t)outlen);
}

/* ---------- hex 工具 ---------- */

static void m4_hex_encode(const unsigned char *d, int n, char *out) {
    static const char *HEX = "0123456789abcdef";
    int i;
    for (i = 0; i < n; i++) {
        out[2*i]   = HEX[d[i] >> 4];
        out[2*i+1] = HEX[d[i] & 0xF];
    }
    out[2*n] = 0;
}

/* ---------- 业务核心（App 与玩家对拍的是同一套实现） ---------- */

static void m4_core_enc(int page, long long ts, char hex[65]) {
    char payload[32];
    unsigned char key[16];
    int n, i;
    n = snprintf(payload, sizeof(payload), "page=%d&ts=%lld", page, ts);
    if (n < 0) n = 0;
    if (n > 31) n = 31;
    memset(payload + n, 0, (size_t)(32 - n));
    m4_derive("|rc4", key, 16);
    m4_rc4(key, 16, (unsigned char *)payload, 32);
    m4_hex_encode((const unsigned char *)payload, 32, hex);
}

static void m4_core_sign(const char *enc, char hex[65]) {
    unsigned char mk[32], dg[32];
    size_t elen = strlen(enc);
    if (elen > 120) elen = 120;
    m4_derive("|mac", mk, 32);
    m4_hmac_sha256(mk, 32, (const unsigned char *)enc, (unsigned int)elen, dg);
    m4_hex_encode(dg, 32, hex);
}

/* ---------- 导出面 ---------- */

/* 诱饵密文：拿去配真算法会解出一段“像样”的假载荷，别当真 */
const char *m4_decoy_seal(void) {
    static char hex[65];
    m4_hex_encode(DECOY_BLOB, 32, hex);
    return hex;
}

/* 噪声导出：无人调用，纯占位混淆 */
static volatile unsigned int m4_sink;

int m4_fold(unsigned int x) {
    unsigned int v = x;
    int i;
    for (i = 0; i < 4; i++) v = (v ^ (v << 3)) + 0x9E3779B9U;
    m4_sink = v;
    return (int)(v & 0xFFFF);
}

unsigned int m4_spin(unsigned int x, int n) {
    unsigned int v = (n & 31) ? ((x << (n & 31)) | (x >> (32 - (n & 31)))) : x;
    m4_sink = v ^ m4_sink;
    return v;
}

#ifndef M4_HOST_TEST

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Vr_nativeEnc(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char hex[65];
    (void)clazz;
    m4_core_enc((int)page, (long long)ts, hex);
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Vr_nativeSign(JNIEnv *env, jclass clazz, jstring enc) {
    char hex[65];
    const char *e;
    (void)clazz;
    if (!enc) return (*env)->NewStringUTF(env, "ERR_INPUT");
    e = (*env)->GetStringUTFChars(env, enc, NULL);
    if (!e) return (*env)->NewStringUTF(env, "ERR_UTF");
    m4_core_sign(e, hex);
    (*env)->ReleaseStringUTFChars(env, enc, e);
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;(void)reserved;
    return JNI_VERSION_1_6;
}

#endif /* !M4_HOST_TEST */

#ifdef M4_HOST_TEST
/* 主机自测：cc -DM4_HOST_TEST -o m4test m4.c && ./m4test */
int main(void) {
    char enc[65], sign[65];
    unsigned char key[16], work[33];
    int i;
    m4_core_enc(1, 1787013761LL, enc);
    m4_core_sign(enc, sign);
    printf("sample_enc  = %s\n", enc);
    printf("sample_sign = %s\n", sign);
    /* 回环：流异或自反，再跑一遍即还原 */
    m4_derive("|rc4", key, 16);
    for (i = 0; i < 32; i++) {
        char c1 = enc[2*i], c2 = enc[2*i+1];
        int hi = (c1<='9')?(c1-'0'):(c1-'a'+10);
        int lo = (c2<='9')?(c2-'0'):(c2-'a'+10);
        work[i] = (unsigned char)((hi<<4)|lo);
    }
    work[32] = 0;
    m4_rc4(key, 16, work, 32);
    printf("roundtrip   = %s\n", work);
    return 0;
}
#endif
"""


def main():
    self_test()

    csrc = C_TEMPLATE
    csrc = csrc.replace("@KSAINIT@", fmt_bytes(bytes(KSA_INIT)))
    csrc = csrc.replace("@XMASK@", fmt_bytes(MASK))
    csrc = csrc.replace("@MARKLEN@", str(len(MARKER)))
    csrc = csrc.replace("@MARKER@", fmt_units([ord(ch) for ch in MARKER]))
    csrc = csrc.replace("@DECOY@", DECOY_MARKER)
    csrc = csrc.replace("@DBLOB@", fmt_bytes(DECOY_BLOB))

    out_path = "app/jni/m4.c"
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(csrc)

    sample_page, sample_ts = 1, 1787013761
    enc = core_enc(sample_page, sample_ts).hex()
    print()
    print("[emit] %s (%d lines)" % (out_path, csrc.count("\n") + 1))
    print("[info] marker       =", MARKER, "(UTF-16 hidden)")
    print("[info] decoy mark   =", DECOY_MARKER, "(plain strings-visible)")
    print("[info] rc4_key      =", RC4_KEY.hex())
    print("[info] mac_key      =", MAC_KEY.hex())
    print("[info] xor_mask     =", MASK.hex())
    print("[info] decoy_key    =", DECOY_KEY.hex())
    print("[info] decoy_blob   =", DECOY_BLOB.hex())
    print("[check] decoy_blob decrypt ->",
          rc4_crypt(KSA_INIT, MASK, DECOY_KEY, DECOY_BLOB).rstrip(b"\x00").decode())
    print("[sample] page=%d ts=%d" % (sample_page, sample_ts))
    print("[sample] enc  =", enc)
    print("[sample] sign =", core_sign(enc))


if __name__ == "__main__":
    main()
