/* libm2.so ——「裂魂之匣」（由 gen_kl7.py 生成，勿手改）
 * 手写 DES：骨架全部可认（S1 开头 14,04,0d,01、E/P/PC1/PC2 标准），但有三处被动手脚：
 *   ① IP 排列表首尾互换：IP[0]=58 <-> IP[63]=57（IDA 里对表一眼见血）
 *   ② FP 同步重算为魔改 IP 的逆置换（保证自身加解密回环一致）
 *   ③ S3 盒第 2 行第 3/4 列两值互换（13 <-> 8）
 * 因此标准 DES 实现解不开本关密文。
 *
 * 密钥全部运行时派生：
 *   des_key = sha256(<标记>|"des") 前 24 字节 —— 3DES-EDE（E/D/E 三层全是魔改 DES）
 *   mac     = sha256(<标记>|"mac") 全 32 字节
 * 真标记存成 UTF-16 码元数组（非 const 全局），默认 strings 不显示；
 * 另有一个明文诱饵标记与一段假密文等着粗心的猎物。
 */
#include <string.h>
#include <stdio.h>

#ifndef M2_HOST_TEST
#include <jni.h>
#endif

/* 初始置换 IP：注意首位是 57 不是 58——本关魔改点① */
static const unsigned char IP[64] = {
        7,50,42,34,26,18,10,2,
        60,52,44,36,28,20,12,4,
        62,54,46,38,30,22,14,6,
        64,56,48,40,32,24,16,8,
        57,49,41,33,25,17,9,1,
        59,51,43,35,27,19,11,3,
        61,53,45,37,29,21,13,5,
        63,55,47,39,31,23,15,58,
};

/* 逆初始置换 FP：随魔改 IP 同步重算（魔改点②） */
static const unsigned char FP[64] = {
        40,8,48,16,56,24,1,32,
        39,7,47,15,55,23,63,31,
        38,6,46,14,54,22,62,30,
        37,5,45,13,53,21,61,29,
        36,4,44,12,52,20,60,28,
        35,3,43,11,51,19,59,27,
        34,2,42,10,50,18,58,26,
        33,64,41,9,49,17,57,25,
};

/* 扩展置换 E（标准） */
static const unsigned char E48[48] = {
        32,1,2,3,4,5,
        4,5,6,7,8,9,
        8,9,10,11,12,13,
        12,13,14,15,16,17,
        16,17,18,19,20,21,
        20,21,22,23,24,25,
        24,25,26,27,28,29,
        28,29,30,31,32,1,
};

/* PC1 / PC2 / 移位表（标准） */
static const unsigned char PC1[56] = {
        57,49,41,33,25,17,9,
        1,58,50,42,34,26,18,
        10,2,59,51,43,35,27,
        19,11,3,60,52,44,36,
        63,55,47,39,31,23,15,
        7,62,54,46,38,30,22,
        14,6,61,53,45,37,29,
        21,13,5,28,20,12,4,
};
static const unsigned char PC2[48] = {
        14,17,11,24,1,5,
        3,28,15,6,21,10,
        23,19,12,4,26,8,
        16,7,27,20,13,2,
        41,52,31,37,47,55,
        30,40,51,45,33,48,
        44,49,39,56,34,53,
        46,42,50,36,29,32,
};
static const unsigned char SHIFTS[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

/* P 置换（标准） */
static const unsigned char PT[32] = {
        16,7,20,21,29,12,28,17,
        1,15,23,26,5,18,31,10,
        2,8,24,14,32,27,3,9,
        19,13,30,6,22,11,4,25,
};

/* 8 个 S 盒：S1 开头 14,04,0d,01 可认出骨架；S3 第 18/19 位是 9,00 不是 00,09——魔改点③ */
static const unsigned char SBOX[8][64] = {
        { /* S1 */
        14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
        0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
        4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
        15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13,
        },
        { /* S2 */
        15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
        3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
        0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
        13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9,
        },
        { /* S3（第 18/19 位 9,00 为魔改：原 00,09） */
        10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
        13,7,9,0,3,4,6,10,2,8,5,14,12,11,15,1,
        13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
        1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12,
        },
        { /* S4 */
        7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
        13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
        10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
        3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14,
        },
        { /* S5 */
        2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
        14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
        11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3,
        },
        { /* S6 */
        12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
        10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
        4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13,
        },
        { /* S7 */
        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
        13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
        1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
        6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12,
        },
        { /* S8 */
        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
        1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
        7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
        2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11,
        },
};

/* 真标记 UTF-16 码元：非 static 非 const 全局，防止编译器常量折叠进指令流 */
unsigned short MARK[14] = {
        0x0046, 0x0061, 0x0074, 0x0064, 0x006f, 0x0067, 0x005f, 0x0073,
        0x0068, 0x0061, 0x0074, 0x0074, 0x0065, 0x0072,
};

/* 明文诱饵标记：非 static 保证落盘，strings 一眼可见，一字之差 */
const char DECOY_MARK[] = "Fatdog_scatter";

/* 假密文：用诱饵标记派生的钥加密的一段"像样"假载荷 */
static const unsigned char DECOY_BLOB[24] = {
        0xb0,0x6f,0x4f,0x53,0x59,0x8d,0x7a,0xb0,0x03,0xbd,0x48,0x53,
        0xd2,0x96,0x90,0x5c,0xbd,0xb8,0xa0,0x05,0x99,0xe4,0x49,0xa3,
};

/* ---------- SHA-256（任意长度） ---------- */

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

static unsigned int m2_rotr(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }

static void m2_sha_block(unsigned int h[8], const unsigned char p[64]) {
    unsigned int w[64];
    unsigned int a,b,c,d,e,f,g,hh,t1,t2,S0,S1,mj;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[4*i]<<24)|((unsigned int)p[4*i+1]<<16)
             | ((unsigned int)p[4*i+2]<<8)|(unsigned int)p[4*i+3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = m2_rotr(w[i-15],7) ^ m2_rotr(w[i-15],18) ^ (w[i-15]>>3);
        unsigned int s1 = m2_rotr(w[i-2],17) ^ m2_rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        S1 = m2_rotr(e,6)^m2_rotr(e,11)^m2_rotr(e,25);
        t1 = hh + S1 + ((e&f)^((~e)&g)) + K256[i] + w[i];
        S0 = m2_rotr(a,2)^m2_rotr(a,13)^m2_rotr(a,22);
        mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

static void m2_sha256(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned int h[8];
    unsigned int off;
    unsigned char tail[128];
    unsigned int rem, tlen, i;
    unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
    h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
    for (off = 0; off + 64 <= len; off += 64)
        m2_sha_block(h, msg + off);
    rem = len - off;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++)
        tail[tlen - 1 - i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    m2_sha_block(h, tail);
    if (tlen == 128) m2_sha_block(h, tail + 64);
    for (i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(h[i]>>24);
        out[4*i+1] = (unsigned char)(h[i]>>16);
        out[4*i+2] = (unsigned char)(h[i]>>8);
        out[4*i+3] = (unsigned char)(h[i]);
    }
}

/* HMAC-SHA256：消息不超过 96 字节（本关只签 72 字符 hex），栈上拼装即可 */
static void m2_hmac_sha256(const unsigned char *key, unsigned int klen,
                           const unsigned char *msg, unsigned int mlen,
                           unsigned char out[32]) {
    unsigned char k0[64], ipad[64], opad[64], ih[32], buf[192];
    unsigned int i;
    memset(k0, 0, sizeof(k0));
    if (klen > 64) m2_sha256(key, klen, k0);
    else memcpy(k0, key, klen);
    for (i = 0; i < 64; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    if (mlen > 120) mlen = 120;
    memcpy(buf, ipad, 64);
    memcpy(buf + 64, msg, mlen);
    m2_sha256(buf, 64 + mlen, ih);
    memcpy(buf, opad, 64);
    memcpy(buf + 64, ih, 32);
    m2_sha256(buf, 96, out);
}

/* ---------- 魔改 DES 核心（位串实现，与生成器逐句镜像） ---------- */

static void m2_bytes_to_bits(const unsigned char *b, unsigned char bits[64]) {
    int i, j;
    for (i = 0; i < 8; i++)
        for (j = 0; j < 8; j++)
            bits[i*8+j] = (unsigned char)((b[i] >> (7 - j)) & 1);
}

static void m2_bits_to_bytes(const unsigned char *bits, unsigned char *b) {
    int i;
    memset(b, 0, 8);
    for (i = 0; i < 64; i++)
        if (bits[i]) b[i>>3] |= (unsigned char)(0x80u >> (i & 7));
}

/* 子密钥编排：16 轮 48 位子密钥 */
static void m2_key_schedule(const unsigned char *key8, unsigned char rks[16][48]) {
    unsigned char bits[64], pc1[56], c[28], d[28], cd[56];
    int r, i, j, s;
    m2_bytes_to_bits(key8, bits);
    for (i = 0; i < 56; i++) pc1[i] = bits[PC1[i]-1];
    memcpy(c, pc1, 28); memcpy(d, pc1+28, 28);
    for (r = 0; r < 16; r++) {
        s = SHIFTS[r];
        for (i = 0; i < s; i++) {
            unsigned char t = c[0];
            for (j = 0; j < 27; j++) c[j] = c[j+1];
            c[27] = t;
            t = d[0];
            for (j = 0; j < 27; j++) d[j] = d[j+1];
            d[27] = t;
        }
        memcpy(cd, c, 28); memcpy(cd+28, d, 28);
        for (i = 0; i < 48; i++) rks[r][i] = cd[PC2[i]-1];
    }
}

/* Feistel 轮函数 f(R,K)：扩展 -> 异或 -> S 盒压缩 -> P 置换 */
static void m2_f(const unsigned char r[32], const unsigned char k[48],
                 unsigned char out[32]) {
    unsigned char e[48], x[48], sb[32];
    int i, j;
    for (i = 0; i < 48; i++) e[i] = r[E48[i]-1];
    for (i = 0; i < 48; i++) x[i] = (unsigned char)(e[i] ^ k[i]);
    for (i = 0; i < 8; i++) {
        int b0=x[i*6], b1=x[i*6+1], b2=x[i*6+2], b3=x[i*6+3], b4=x[i*6+4], b5=x[i*6+5];
        int row = b0*2 + b5;
        int col = b1*8 + b2*4 + b3*2 + b4;
        int val = SBOX[i][row*16 + col];
        for (j = 0; j < 4; j++) sb[i*4+j] = (unsigned char)((val >> (3-j)) & 1);
    }
    for (i = 0; i < 32; i++) out[i] = sb[PT[i]-1];
}

static void m2_enc_block(const unsigned char *in, unsigned char *out,
                         unsigned char rks[16][48]) {
    unsigned char bits[64], st[64], l[32], r[32], nf[32], t[32];
    int rnd, i;
    m2_bytes_to_bits(in, bits);
    for (i = 0; i < 64; i++) st[i] = bits[IP[i]-1];
    memcpy(l, st, 32); memcpy(r, st+32, 32);
    for (rnd = 0; rnd < 16; rnd++) {
        m2_f(r, rks[rnd], nf);
        for (i = 0; i < 32; i++) t[i] = (unsigned char)(l[i] ^ nf[i]);
        memcpy(l, r, 32);
        memcpy(r, t, 32);
    }
    /* 输出前交换：R16 || L16 */
    memcpy(st, r, 32); memcpy(st+32, l, 32);
    for (i = 0; i < 64; i++) bits[i] = st[FP[i]-1];
    m2_bits_to_bytes(bits, out);
}

static void m2_dec_block(const unsigned char *in, unsigned char *out,
                         unsigned char rks[16][48]) {
    unsigned char rev[16][48];
    int r, i;
    for (r = 0; r < 16; r++)
        for (i = 0; i < 48; i++) rev[r][i] = rks[15-r][i];
    m2_enc_block(in, out, rev);
}

/* 3DES-EDE：c = E(K3, D(K2, E(K1, p)))——三层全是魔改 DES */
static void m2_ede_encrypt(const unsigned char key24[24],
                           const unsigned char *data, int len,
                           unsigned char *out) {
    unsigned char k1[16][48], k2[16][48], k3[16][48];
    unsigned char a[8], b[8];
    int off;
    m2_key_schedule(key24, k1);
    m2_key_schedule(key24+8, k2);
    m2_key_schedule(key24+16, k3);
    for (off = 0; off + 8 <= len; off += 8) {
        m2_enc_block(data+off, a, k1);
        m2_dec_block(a, b, k2);
        m2_enc_block(b, out+off, k3);
    }
}

/* 标记运行时拼装 + 派生：suffix 形如 "|des"/"|mac" */
static void m2_derive(const char *suffix, unsigned char *out, int outlen) {
    char mk[32];
    char msg[48];
    unsigned char dg[32];
    int i, n = sizeof(MARK) / sizeof(unsigned short);
    int slen = (int)strlen(suffix);
    for (i = 0; i < n; i++) mk[i] = (char)(MARK[i] & 0xFF);
    mk[n] = 0;
    memcpy(msg, mk, (size_t)n);
    memcpy(msg + n, suffix, (size_t)slen);
    m2_sha256((const unsigned char *)msg, (unsigned int)(n + slen), dg);
    memcpy(out, dg, (size_t)outlen);
}

/* ---------- hex 工具 ---------- */

static void m2_hex_encode(const unsigned char *d, int n, char *out) {
    static const char *HEX = "0123456789abcdef";
    int i;
    for (i = 0; i < n; i++) {
        out[2*i]   = HEX[d[i] >> 4];
        out[2*i+1] = HEX[d[i] & 0xF];
    }
    out[2*n] = 0;
}

/* ---------- 业务核心（App 与玩家对拍的是同一套实现） ---------- */

static void m2_core_enc(int page, long long ts, char hex[73]) {
    char payload[32];
    unsigned char pt[24], ct[24], key[24];
    int n, i;
    n = snprintf(payload, sizeof(payload), "page=%d&ts=%lld", page, ts);
    if (n < 0) n = 0;
    if (n > 23) n = 23;
    memset(pt, 0, sizeof(pt));
    for (i = 0; i < n && i < 24; i++) pt[i] = (unsigned char)payload[i];
    m2_derive("|des", key, 24);
    m2_ede_encrypt(key, pt, 24, ct);
    m2_hex_encode(ct, 24, hex);
}

static void m2_core_sign(const char *enc, char hex[65]) {
    unsigned char mk[32], dg[32];
    size_t elen = strlen(enc);
    if (elen > 120) elen = 120;
    m2_derive("|mac", mk, 32);
    m2_hmac_sha256(mk, 32, (const unsigned char *)enc, (unsigned int)elen, dg);
    m2_hex_encode(dg, 32, hex);
}

/* ---------- 导出面 ---------- */

/* 诱饵密文：拿去配真算法会解出一段"像样"的假载荷，别当真 */
const char *m2_decoy_seal(void) {
    static char hex[49];
    m2_hex_encode(DECOY_BLOB, 24, hex);
    return hex;
}

/* 噪声导出：无人调用，纯占位混淆 */
static volatile unsigned int m2_sink;

int m2_fold(unsigned int x) {
    unsigned int v = x;
    int i;
    for (i = 0; i < 4; i++) v = (v ^ (v << 3)) + 0x9E3779B9U;
    m2_sink = v;
    return (int)(v & 0xFFFF);
}

unsigned int m2_spin(unsigned int x, int n) {
    unsigned int v = (n & 31) ? ((x << (n & 31)) | (x >> (32 - (n & 31)))) : x;
    m2_sink = v ^ m2_sink;
    return v;
}

#ifndef M2_HOST_TEST

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Tp_nativeEncDes(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char hex[73];
    (void)clazz;
    m2_core_enc((int)page, (long long)ts, hex);
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Tp_nativeSign(JNIEnv *env, jclass clazz, jstring enc) {
    char hex[65];
    const char *e;
    (void)clazz;
    if (!enc) return (*env)->NewStringUTF(env, "ERR_INPUT");
    e = (*env)->GetStringUTFChars(env, enc, NULL);
    if (!e) return (*env)->NewStringUTF(env, "ERR_UTF");
    m2_core_sign(e, hex);
    (*env)->ReleaseStringUTFChars(env, enc, e);
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;(void)reserved;
    return JNI_VERSION_1_6;
}

#endif /* !M2_HOST_TEST */

#ifdef M2_HOST_TEST
/* 主机自测：cc -DM2_HOST_TEST -o m2test m2.c && ./m2test */
int main(void) {
    char enc[73], sign[65];
    unsigned char key[24], pt[24], back[25];
    int i, j;
    m2_core_enc(1, 1787013761LL, enc);
    m2_core_sign(enc, sign);
    printf("sample_enc  = %s\n", enc);
    printf("sample_sign = %s\n", sign);
    printf("decoy_seal  = %s\n", m2_decoy_seal());
    /* 回环：用同一把钥匙解开自己的密文 */
    m2_derive("|des", key, 24);
    memset(back, 0, sizeof(back));
    for (i = 0; i < 24; i += 8) {
        unsigned char ct[8], mid1[8], mid2[8], k1[16][48], k2[16][48], k3[16][48];
        for (j = 0; j < 8; j++) {
            char c1 = enc[2*(i+j)], c2 = enc[2*(i+j)+1];
            int hi = (c1<='9')?(c1-'0'):(c1-'a'+10);
            int lo = (c2<='9')?(c2-'0'):(c2-'a'+10);
            ct[j] = (unsigned char)((hi<<4)|lo);
        }
        m2_key_schedule(key, k1);
        m2_key_schedule(key+8, k2);
        m2_key_schedule(key+16, k3);
        m2_dec_block(ct, mid1, k3);
        m2_enc_block(mid1, mid2, k2);
        m2_dec_block(mid2, back + i, k1);
    }
    back[24] = 0;
    printf("roundtrip   = %s\n", back);
    return 0;
}
#endif
