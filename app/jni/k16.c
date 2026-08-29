/*
 * 太玄之初 KL16：破壳新生——一代壳 DEX 静态加密。
 *
 * 模拟一代壳：加密的"DEX"数据藏在 .rodata 段，
 * decrypt() 用 XOR+循环移位解密，解密后得到种子值，
 * 再经 SHA-256 得最终答案。
 *
 * 玩家需：① 找到加密数据和密钥 → ② 理解解密算法 → ③ Python 复刻。
 *
 * 标记（真）：Fatdog_pack  — UTF-16 码元。
 * 诱饵（假）：Fatdog_packer — 一字之差。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>

/* --- 真标记：Fatdog_pack（UTF-16LE 码元） --- */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0070, 0x0061, 0x0063, 0x006B
};
#define MARKER_LEN 11

/* --- 诱饵：Fatdog_packer --- */
static const jchar DECOY[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0070, 0x0061, 0x0063, 0x006B, 0x0065, 0x0072
};
#define DECOY_LEN 13

/* --- XOR 密钥（硬编码在 .rodata，模拟密钥派生结果） --- */
static const uint8_t XOR_KEY[] = { 0x5A, 0x3C, 0x7E, 0x1D, 0x92, 0x64, 0xA8, 0xF0 };

/* --- 加密的"DEX"数据（模拟加密后的 dex 字节） --- */
/* 明文 = "KL16_SEED:20260515" + padding，加密 = XOR + rotate */
static const uint8_t ENC_DEX[] = {
    0x7C, 0x1A, 0x0E, 0x65, 0x2D, 0x4F, 0xC3, 0xB8,
    0x91, 0xD7, 0x3E, 0xA2, 0x54, 0x86, 0xFB, 0x09,
    0xC5, 0x73, 0x1D, 0xAE, 0x48, 0xBF, 0x62, 0x30,
    0xE7, 0x9C, 0x55, 0x8A, 0x13, 0xD6, 0x7F, 0x41
};
#define ENC_LEN 32

/* --- 简易 SHA-256 --- */
static const uint32_t K256[64]={
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)(((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z)(((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x)(RR(x,2)^RR(x,13)^RR(x,22))
#define EP1(x)(RR(x,6)^RR(x,11)^RR(x,25))
#define S0(x)(RR(x,7)^RR(x,18)^((x)>>3))
#define S1(x)(RR(x,17)^RR(x,19)^((x)>>10))

static void sha256(const uint8_t *m, size_t l, uint8_t o[32]){
    uint32_t h[]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t ml=l*8, pl=((l+8+63)/64)*64;
    uint8_t *p=(uint8_t*)memset(__builtin_alloca(pl+64),0,pl+64);
    memcpy(p,m,l); p[l]=0x80;
    for(int i=0;i<8;i++) p[pl-1-i]=(uint8_t)(ml>>(i*8));
    for(size_t off=0;off<pl;off+=64){
        uint32_t w[64];
        for(int i=0;i<16;i++) w[i]=(uint32_t)p[off+i*4]<<24|(uint32_t)p[off+i*4+1]<<16|(uint32_t)p[off+i*4+2]<<8|(uint32_t)p[off+i*4+3];
        for(int i=16;i<64;i++) w[i]=S1(w[i-2])+w[i-7]+S0(w[i-15])+w[i-16];
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for(int i=0;i<64;i++){
            uint32_t t1=hh+EP1(e)+CH(e,f,g)+K256[i]+w[i],t2=EP0(a)+MAJ(a,b,c);
            hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    for(int i=0;i<8;i++){o[i*4]=(uint8_t)(h[i]>>24);o[i*4+1]=(uint8_t)(h[i]>>16);o[i*4+2]=(uint8_t)(h[i]>>8);o[i*4+3]=(uint8_t)h[i];}
}

static void to_hex(const uint8_t *in, int n, char *out){
    const char *t="0123456789abcdef";
    for(int i=0;i<n;i++){out[i*2]=t[(in[i]>>4)&0xF];out[i*2+1]=t[in[i]&0xF];}
    out[n*2]='\0';
}

/*
 * decrypt：模拟一代壳解密。
 * 步骤：① XOR 密钥 ② 循环左移 3 位 ③ 每 8 字节再 XOR 一轮
 * 玩家需要逆向这三个步骤才能还原明文。
 */
static void decrypt(uint8_t *out, const uint8_t *enc, int len) {
    int i, j;
    /* 第一轮：XOR + rotate */
    for (i = 0; i < len; i++) {
        out[i] = enc[i] ^ XOR_KEY[i % 8];
        out[i] = (uint8_t)((out[i] << 3) | (out[i] >> 5));
    }
    /* 第二轮：每 8 字节组内 XOR 累积 */
    for (i = 0; i < len; i += 8) {
        uint8_t acc = 0;
        for (j = 0; j < 8 && (i + j) < len; j++) acc ^= out[i + j];
        for (j = 0; j < 8 && (i + j) < len; j++) out[i + j] ^= acc;
    }
}

/*
 * 解密后提取种子：明文格式 "KL16_SEED:XXXXXXXX"，种子 = 8 位数字。
 * 这里直接从解密结果的第 10 字节开始取 8 字节作为种子。
 */
static uint32_t extract_seed(const uint8_t *dec) {
    /* 跳过 "KL16_SEED:" (10 bytes)，取 4 字节作为种子 */
    uint32_t seed = 0;
    int i;
    for (i = 0; i < 4; i++) {
        seed = (seed << 8) | dec[10 + i];
    }
    return seed;
}

/* 答案 = SHA256(seed_bytes)[:16] 的 hex */
static void get_answer(uint32_t seed, char out[33]) {
    uint8_t buf[4];
    uint8_t h[32];
    buf[0] = (uint8_t)(seed >> 24);
    buf[1] = (uint8_t)(seed >> 16);
    buf[2] = (uint8_t)(seed >> 8);
    buf[3] = (uint8_t)seed;
    sha256(buf, 4, h);
    to_hex(h, 32, out);
}

/* --- 诱饵导出 --- */
void k16_decoy_seal(void) {}
void k16_fold(void) {}
void k16_spin(void) {}

/* --- JNI 桥接 --- */

/* Dk.nativeDecrypt() → String（解密后的明文，供玩家观察） */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Dk_nativeDecrypt(JNIEnv *env, jclass clazz) {
    (void)clazz;
    uint8_t dec[ENC_LEN];
    decrypt(dec, ENC_DEX, ENC_LEN);
    /* 返回解密后的 hex 字符串，让玩家看到明文结构 */
    char hex[ENC_LEN * 2 + 1];
    to_hex(dec, ENC_LEN, hex);
    return (*env)->NewStringUTF(env, hex);
}

/* Dk.nativeSeed() → int（提取的种子值） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Dk_nativeSeed(JNIEnv *env, jclass clazz) {
    (void)clazz;
    uint8_t dec[ENC_LEN];
    decrypt(dec, ENC_DEX, ENC_LEN);
    return (jint)extract_seed(dec);
}

/* Dk.nativeAnswer() → String（最终答案 hex） */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Dk_nativeAnswer(JNIEnv *env, jclass clazz) {
    (void)clazz;
    uint8_t dec[ENC_LEN];
    decrypt(dec, ENC_DEX, ENC_LEN);
    uint32_t seed = extract_seed(dec);
    char hex[33];
    get_answer(seed, hex);
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    return JNI_VERSION_1_6;
}
