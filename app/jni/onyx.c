/* libm5.so ——「万象归一」（由 gen_kl10.py 生成，勿手改）
 * 双层叠加签名：sign = hex( 魔改AES-128-ECB( aes_key, 魔改SHA256(payload) ) )
 *   第一层 SHA256 变体：K 表与压缩轮全标准（认骨架看 K 表 428a2f98…），
 *     但初始 IV 整组换血为派生值，且消息填充边界从 56 前移到 48（多补一轮压缩）。
 *   第二层 AES-128：S 盒/轮结构全标准（认骨架看 S 盒 63 7c 77 7b…），
 *     但 MixColumns 系数 {2,3} 对调为 {3,2}。
 * 密钥运行时派生：iv = sha256(<标记>|"iv")；aes_key = sha256(<标记>|"key")[:16]。
 * 真标记 UTF-16 码元藏匿（strings 盲区）；明文诱饵 Fatdog_ellipse 一字之差。
 */
#include <string.h>
#include <stdio.h>

#ifndef M5_HOST_TEST
#include <jni.h>
#endif

static const unsigned char SBOX[256] = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,
        0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
        0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,
        0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,
        0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,
        0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,
        0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,
        0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,
        0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,
        0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,
        0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,
        0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,
        0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,
        0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,
        0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,
        0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,
        0xb0,0x54,0xbb,0x16,
};

/* 真标记 UTF-16 码元：非 static 非 const 全局，防止编译器常量折叠进指令流 */
unsigned short MARK[14] = {
        0x0046, 0x0061, 0x0074, 0x0064, 0x006f, 0x0067, 0x005f, 0x0065,
        0x0063, 0x006c, 0x0069, 0x0070, 0x0073, 0x0065,
};

/* 明文诱饵标记：非 static 保证落盘，strings 一眼可见，一字之差 */
const char DECOY_MARK[] = "Fatdog_ellipse";

/* 假密文：用诱饵标记派生的钥加密的一段“像样”假载荷 */
static const unsigned char DECOY_BLOB[32] = {
        0x70,0x7a,0xae,0x2e,0x9e,0x8d,0x09,0xb2,0xdb,0x2a,0x33,0x49,
        0x42,0xc7,0x61,0xf1,0x63,0xbb,0xd3,0xca,0x54,0xf7,0x4f,0xcd,
        0x83,0x9c,0x44,0x01,0x56,0x7a,0xde,0xd6,
};

/* ---------- SHA-256 变体（自定义 IV + 48 边界填充；消息 <48 字节单块足够） ---------- */

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

static unsigned int m5_rotr(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }

/* 变体摘要：h[] 由派生 IV 装载；填充边界 BOUNDARY=48（长度域在 48..55） */
#define M5_BOUNDARY 48

static void m5_sha_block(unsigned int h[8], const unsigned char p[64]) {
    unsigned int w[64];
    unsigned int a,b,c,d,e,f,g,hh,t1,t2,S0,S1,mj;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[4*i]<<24)|((unsigned int)p[4*i+1]<<16)
             | ((unsigned int)p[4*i+2]<<8)|(unsigned int)p[4*i+3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = m5_rotr(w[i-15],7) ^ m5_rotr(w[i-15],18) ^ (w[i-15]>>3);
        unsigned int s1 = m5_rotr(w[i-2],17) ^ m5_rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        S1 = m5_rotr(e,6)^m5_rotr(e,11)^m5_rotr(e,25);
        t1 = hh + S1 + ((e&f)^((~e)&g)) + K256[i] + w[i];
        S0 = m5_rotr(a,2)^m5_rotr(a,13)^m5_rotr(a,22);
        mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

static void m5_derive(const char *suffix, unsigned char *out, int outlen);
static void m5_std_sha(const unsigned char *msg, unsigned int len, unsigned char out[32]);

static void m5_sha_variant(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned char h_bytes[32];
    unsigned int h[8];
    unsigned char tail[128];
    unsigned long long bits = (unsigned long long)len * 8ULL;
    int i;
    /* 初始 IV 来自运行时派生（明文字面量会被 strings 一把梭） */
    m5_derive("|iv", h_bytes, 32);
    for (i = 0; i < 8; i++)
        h[i] = ((unsigned int)h_bytes[4*i]<<24)|((unsigned int)h_bytes[4*i+1]<<16)
             | ((unsigned int)h_bytes[4*i+2]<<8)|(unsigned int)h_bytes[4*i+3];
    if (len > M5_BOUNDARY - 1) len = M5_BOUNDARY - 1; /* 派生场景恒短消息，钳制即可 */
    memset(tail, 0, sizeof(tail));
    memcpy(tail, msg, len);
    tail[len] = 0x80;
    for (i = 0; i < 8; i++)
        tail[M5_BOUNDARY + i] = (unsigned char)((bits >> (8 * (7 - i))) & 0xFF);
    m5_sha_block(h, tail);
    for (i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(h[i]>>24);
        out[4*i+1] = (unsigned char)(h[i]>>16);
        out[4*i+2] = (unsigned char)(h[i]>>8);
        out[4*i+3] = (unsigned char)(h[i]);
    }
}

/* ---------- 魔改 AES-128 加密（MixColumns {2,3} -> {3,2}） ---------- */

static const unsigned char RCON_TAB[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static void m5_ark(unsigned char s[16], const unsigned char k[16]) {
    int i; for (i = 0; i < 16; i++) s[i] ^= k[i];
}

static void m5_key_expand(const unsigned char *key, unsigned char rk[11][16]) {
    int i, j;
    unsigned char t[4];
    memcpy(rk[0], key, 16);
    for (i = 1; i <= 10; i++) {
        const unsigned char *p = rk[i-1];
        unsigned char *c = rk[i];
        t[0] = SBOX[p[13]] ^ RCON_TAB[i-1];
        t[1] = SBOX[p[14]];
        t[2] = SBOX[p[15]];
        t[3] = SBOX[p[12]];
        for (j = 0; j < 4; j++) c[j] = p[j] ^ t[j];
        for (j = 4; j < 16; j++) c[j] = p[j] ^ c[j-4];
    }
}


static unsigned char m5_xt(unsigned char a) {
    return (unsigned char)((a & 0x80) ? ((a << 1) ^ 0x1B) : (a << 1));
}

static unsigned char m5_gmul(unsigned char a, unsigned char b) {
    unsigned char r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = m5_xt(a);
        b >>= 1;
    }
    return r;
}

static void m5_mix(unsigned char s[16]) {
    /* 本关魔改点：系数 {2,3} 对调为 {3,2} */
    int c;
    for (c = 0; c < 4; c++) {
        unsigned char a0=s[4*c],a1=s[4*c+1],a2=s[4*c+2],a3=s[4*c+3];
        s[4*c+0] = m5_gmul(a0,3)^m5_gmul(a1,2)^a2^a3;
        s[4*c+1] = a0^m5_gmul(a1,3)^m5_gmul(a2,2)^a3;
        s[4*c+2] = a0^a1^m5_gmul(a2,3)^m5_gmul(a3,2);
        s[4*c+3] = m5_gmul(a0,2)^a1^a2^m5_gmul(a3,3);
    }
}

static void m5_shift(unsigned char s[16]) {
    unsigned char t;
    t = s[1];  s[1] = s[5];  s[5] = s[9];  s[9] = s[13]; s[13] = t;
    t = s[2];  s[2] = s[10]; s[10] = t;
    t = s[6];  s[6] = s[14]; s[14] = t;
    t = s[3];  s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t;
}


static void m5_enc_block(const unsigned char *in, unsigned char *out,
                         unsigned char rk[11][16]) {
    unsigned char s[16];
    int r, i;
    memcpy(s, in, 16);
    m5_ark(s, rk[0]);
    for (r = 1; r <= 9; r++) {
        for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];
        m5_shift(s);
        m5_mix(s);
        m5_ark(s, rk[r]);
    }
    for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    m5_shift(s);
    m5_ark(s, rk[10]);
    memcpy(out, s, 16);
}

/* 标记运行时拼装 + 派生 */
static void m5_derive(const char *suffix, unsigned char *out, int outlen) {
    char mk[32];
    char msg[48];
    unsigned char dg[32];
    int i, n = sizeof(MARK) / sizeof(unsigned short);
    int slen = (int)strlen(suffix);
    /* 用标准 SHA-256（标准 IV + 标准 56 填充）做密钥派生 */
    for (i = 0; i < n; i++) mk[i] = (char)(MARK[i] & 0xFF);
    mk[n] = 0;
    memcpy(msg, mk, (size_t)n);
    memcpy(msg + n, suffix, (size_t)slen);
    m5_std_sha((const unsigned char *)msg, (unsigned int)(n + slen), dg);
    memcpy(out, dg, (size_t)outlen);
}

/* 标准 SHA-256（仅用于密钥派生；签名第一层用的是上面的变体） */
static void m5_std_sha(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned int h[8];
    unsigned int off, rem, tlen, i;
    unsigned char tail[128];
    unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
    h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
    for (off = 0; off + 64 <= len; off += 64)
        m5_sha_block(h, msg + off);
    rem = len - off;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++)
        tail[tlen - 1 - i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    m5_sha_block(h, tail);
    if (tlen == 128) m5_sha_block(h, tail + 64);
    for (i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(h[i]>>24);
        out[4*i+1] = (unsigned char)(h[i]>>16);
        out[4*i+2] = (unsigned char)(h[i]>>8);
        out[4*i+3] = (unsigned char)(h[i]);
    }
}

/* ---------- hex 工具 ---------- */

static void m5_hex_encode(const unsigned char *d, int n, char *out) {
    static const char *HEX = "0123456789abcdef";
    int i;
    for (i = 0; i < n; i++) {
        out[2*i]   = HEX[d[i] >> 4];
        out[2*i+1] = HEX[d[i] & 0xF];
    }
    out[2*n] = 0;
}

/* ---------- 业务核心 ---------- */

/* 第一层：魔改 SHA256("page=N&ts=T") -> hex */
static void m5_core_digest(int page, long long ts, char hex[65]) {
    char payload[32];
    unsigned char dg[32];
    int n;
    n = snprintf(payload, sizeof(payload), "page=%d&ts=%lld", page, ts);
    if (n < 0) n = 0;
    if (n > 31) n = 31;
    payload[n] = 0;
    m5_sha_variant((const unsigned char *)payload, (unsigned int)n, dg);
    m5_hex_encode(dg, 32, hex);
}

/* 第二层：魔改 AES-ECB(aes_key, digest 32B) -> hex */
static void m5_core_aes(const unsigned char dg32[32], char hex[65]) {
    unsigned char key[16], rk[11][16], ct[32];
    int i;
    m5_derive("|key", key, 16);
    m5_key_expand(key, rk);
    for (i = 0; i < 32; i += 16)
        m5_enc_block(dg32 + i, ct + i, rk);
    m5_hex_encode(ct, 32, hex);
}

/* ---------- 导出面 ---------- */

const char *m5_decoy_seal(void) {
    static char hex[65];
    m5_hex_encode(DECOY_BLOB, 32, hex);
    return hex;
}

static volatile unsigned int m5_sink;

int m5_fold(unsigned int x) {
    unsigned int v = x;
    int i;
    for (i = 0; i < 4; i++) v = (v ^ (v << 3)) + 0x9E3779B9U;
    m5_sink = v;
    return (int)(v & 0xFFFF);
}

unsigned int m5_spin(unsigned int x, int n) {
    unsigned int v = (n & 31) ? ((x << (n & 31)) | (x >> (32 - (n & 31)))) : x;
    m5_sink = v ^ m5_sink;
    return v;
}

#ifndef M5_HOST_TEST

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Ws_nativeDigest(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char hex[65];
    (void)clazz;
    m5_core_digest((int)page, (long long)ts, hex);
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Ws_nativeSign(JNIEnv *env, jclass clazz, jstring digestHex) {
    char hex[65];
    unsigned char dg[32];
    const char *e;
    int i;
    (void)clazz;
    if (!digestHex) return (*env)->NewStringUTF(env, "ERR_INPUT");
    e = (*env)->GetStringUTFChars(env, digestHex, NULL);
    if (!e) return (*env)->NewStringUTF(env, "ERR_UTF");
    for (i = 0; i < 32; i++) {
        char c1 = e[2*i], c2 = e[2*i+1];
        int hi = (c1<='9')?(c1-'0'):(c1-'a'+10);
        int lo = (c2<='9')?(c2-'0'):(c2-'a'+10);
        dg[i] = (unsigned char)((hi<<4)|lo);
    }
    (*env)->ReleaseStringUTFChars(env, digestHex, e);
    m5_core_aes(dg, hex);
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;(void)reserved;
    return JNI_VERSION_1_6;
}

#endif /* !M5_HOST_TEST */

#ifdef M5_HOST_TEST
/* 主机自测：cc -DM5_HOST_TEST -o m5test m5.c && ./m5test */
int main(void) {
    char dig[65], sign[65];
    m5_core_digest(1, 1787013761LL, dig);
    printf("sample_digest = %s\n", dig);
    /* 复用 nativeSign 的解析路径 */
    {
        unsigned char dg[32];
        char sign2[65];
        int i;
        for (i = 0; i < 32; i++) {
            char c1 = dig[2*i], c2 = dig[2*i+1];
            int hi = (c1<='9')?(c1-'0'):(c1-'a'+10);
            int lo = (c2<='9')?(c2-'0'):(c2-'a'+10);
            dg[i] = (unsigned char)((hi<<4)|lo);
        }
        m5_core_aes(dg, sign2);
        printf("sample_sign   = %s\n", sign2);
    }
    (void)sign;
    return 0;
}
#endif
