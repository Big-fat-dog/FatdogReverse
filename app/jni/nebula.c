/*
 * 幽冥海 KL14：偷天换日——多 so 交叉验证（三协同计算）。
 *
 * 三 so 各自产出部分结果，libm13c 拼装后再 hash 得最终答案。
 * libm13b 通过 dlsym 调用 libm13a 的导出函数（交叉调用），
 * patch 任一 so 的计算逻辑或导出符号都会导致最终 hash 不匹配。
 *
 * 破解路线：
 *   ①IDA 分别分析三个 so → 理解各自的计算逻辑 → Python 复刻整条链；
 *   ②Frida 逐个 hook 三个函数拿返回值 → 拼装得答案（无需 patch）；
 *   ③patch 三个 so 的比较点（最费时但教学价值最高）。
 *
 * 标记（真）：Fatdog_mesh  — UTF-16 码元，非 static 非 const 全局存放。
 * 诱饵（假）：Fatdog_mash  — 一字之差陷阱，命中即 403。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>

/* --- 真标记：Fatdog_mesh（UTF-16LE 码元） --- */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067, /* Fatdog */
    0x005F,                                           /* _      */
    0x006D, 0x0065, 0x0073, 0x0068                    /* mesh   */
};
#define MARKER_LEN 11

/* --- 诱饵：Fatdog_mash（e→a） --- */
static const jchar DECOY[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x006D, 0x0061, 0x0073, 0x0068
};
#define DECOY_LEN 11

/* --- 魔数（三 so 各不同） --- */
#define MAGIC 0xAA

/* --- XOR 常量 --- */
#define XOR_KEY 0x0000FACE

/* --- SEED --- */
#define SEED 20280419

/* --- 简易 SHA-256 --- */
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x)      (ROR32(x,2)^ROR32(x,13)^ROR32(x,22))
#define EP1(x)      (ROR32(x,6)^ROR32(x,11)^ROR32(x,25))
#define SIG0(x)     (ROR32(x,7)^ROR32(x,18)^((x)>>3))
#define SIG1(x)     (ROR32(x,17)^ROR32(x,19)^((x)>>10))

static void sha256(const uint8_t *msg, size_t len, uint8_t out[32]) {
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t ml=len*8;
    size_t pl=((len+8+63)/64)*64;
    uint8_t *pad=(uint8_t*)memset(__builtin_alloca(pl+64),0,pl+64);
    memcpy(pad,msg,len);
    pad[len]=0x80;
    for(int i=0;i<8;i++) pad[pl-1-i]=(uint8_t)(ml>>(i*8));
    for(size_t off=0;off<pl;off+=64){
        uint32_t w[64];
        for(int i=0;i<16;i++) w[i]=(uint32_t)pad[off+i*4]<<24|(uint32_t)pad[off+i*4+1]<<16|(uint32_t)pad[off+i*4+2]<<8|(uint32_t)pad[off+i*4+3];
        for(int i=16;i<64;i++) w[i]=SIG1(w[i-2])+w[i-7]+SIG0(w[i-15])+w[i-16];
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[22>>1],hh=h[7];
        for(int i=0;i<64;i++){
            uint32_t t1=hh+EP1(e)+CH(e,f,g)+K256[i]+w[i];
            uint32_t t2=EP0(a)+MAJ(a,b,c);
            hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    for(int i=0;i<8;i++){out[i*4]=(uint8_t)(h[i]>>24);out[i*4+1]=(uint8_t)(h[i]>>16);out[i*4+2]=(uint8_t)(h[i]>>8);out[i*4+3]=(uint8_t)h[i];}
}

/* hex 字符串：小写 */
static void to_hex(const uint8_t *in, int len, char *out) {
    const char *t = "0123456789abcdef";
    int i;
    for (i = 0; i < len; i++) {
        out[i*2]   = t[(in[i] >> 4) & 0x0F];
        out[i*2+1] = t[in[i] & 0x0F];
    }
    out[len*2] = '\0';
}

/* 三步计算：XOR → hash → hex[:8] */
static void compute_digest(int seed, int magic, char out[9]) {
    uint32_t val = (uint32_t)(seed ^ magic);
    uint8_t h[32];
    char hex[65];
    sha256((const uint8_t *)&val, 4, h);
    to_hex(h, 32, hex);
    memcpy(out, hex, 8);
    out[8] = '\0';
}

/* dlsym 跨 so 调用 libm13a 的导出函数 */
static int call_m13a_xor(int a, int b) {
    typedef int (*fn)(int, int);
    fn f = (fn)dlsym(RTLD_DEFAULT, "Java_com_fatdog_reverse_Zn_nativeXor");
    if (f) return f(a, b);
    return a ^ b; /* fallback：libm13a 未加载时走本地 */
}

/* libm13b 导出给 libm13c 调用的跨 so 函数 */
/* 注意：此函数由 libm13b 定义，此处仅声明 extern（链接时解析） */
extern int m13b_get_digest_B(char out[9]);

/* --- 诱饵导出 --- */
void m13a_decoy_seal(void) {}
void m13a_fold(void) {}
void m13a_spin(void) {}

/* --- JNI 桥接 --- */

/* Zn.nativeXor(a, b) → int（跨 so 调用入口） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Zn_nativeXor(JNIEnv *env, jclass clazz, jint a, jint b) {
    (void)env; (void)clazz;
    return a ^ b;
}

/* Zn.nativePartA() → int（digest_A） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Zn_nativePartA(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    uint32_t val = (uint32_t)(SEED ^ MAGIC);
    return (jint)val;
}

/* Zn.nativePartB() → int（交叉调用 libm13b，获取 digest_B 的部分值） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Zn_nativePartB(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    /* 交叉调用：通过 dlsym 调用 libm13b 的导出函数 */
    typedef int (*fn)(char*);
    fn f = (fn)dlsym(RTLD_DEFAULT, "m13b_get_digest_B");
    if (f) {
        char buf[9];
        return (jint)f(buf); /* 返回 digest_B 的整数值 */
    }
    /* fallback：libm13b 未加载时用本地计算 */
    return (jint)((uint32_t)(SEED ^ 0xBB));
}

/* Zn.nativeCombine(int a, int b) → String（最终答案） */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Zn_nativeCombine(JNIEnv *env, jclass clazz, jint a, jint b) {
    (void)clazz;
    /* 拼装 A‖B → SHA-256 → hex[:32] */
    uint8_t buf[8];
    uint8_t h[32];
    char hex[65];
    buf[0]=(uint8_t)(a>>24); buf[1]=(uint8_t)(a>>16); buf[2]=(uint8_t)(a>>8); buf[3]=(uint8_t)a;
    buf[4]=(uint8_t)(b>>24); buf[5]=(uint8_t)(b>>16); buf[6]=(uint8_t)(b>>8); buf[7]=(uint8_t)b;
    sha256(buf, 8, h);
    to_hex(h, 32, hex);
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    return JNI_VERSION_1_6;
}
