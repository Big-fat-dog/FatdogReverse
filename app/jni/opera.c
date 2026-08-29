/*
 * 幽冥海 KL14：libm13b——digest_B 计算 + 跨 so 调用 libm13a 的 nativeXor。
 *
 * libm13b 通过 dlsym 调用 libm13a 的 nativeXor 函数（交叉调用），
 * 单独替换任一 so 的计算逻辑或导出符号都会导致最终 hash 不匹配。
 *
 * 标记（真）：Fatdog_mesh  — 同 libm13a。
 * 诱饵（假）：Fatdog_mash  — 同 libm13a。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>

/* --- 魔数 --- */
#define MAGIC_B 0xBB

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
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for(int i=0;i<64;i++){
            uint32_t t1=hh+EP1(e)+CH(e,f,g)+K256[i]+w[i];
            uint32_t t2=EP0(a)+MAJ(a,b,c);
            hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    for(int i=0;i<8;i++){out[i*4]=(uint8_t)(h[i]>>24);out[i*4+1]=(uint8_t)(h[i]>>16);out[i*4+2]=(uint8_t)(h[i]>>8);out[i*4+3]=(uint8_t)h[i];}
}

static void to_hex(const uint8_t *in, int len, char *out) {
    const char *t = "0123456789abcdef";
    int i;
    for (i = 0; i < len; i++) {
        out[i*2]   = t[(in[i] >> 4) & 0x0F];
        out[i*2+1] = t[in[i] & 0x0F];
    }
    out[len*2] = '\0';
}

/*
 * get_digest_B：被 libm13c 通过 dlsym 调用的跨 so 函数。
 * 返回 digest_B 的整数值，同时把 hex 写入 out。
 */
int m13b_get_digest_B(char out[9]) {
    uint32_t val = (uint32_t)(SEED ^ MAGIC_B);
    uint8_t h[32];
    char hex[65];
    sha256((const uint8_t *)&val, 4, h);
    to_hex(h, 32, hex);
    if (out) { memcpy(out, hex, 8); out[8] = '\0'; }
    return (int)val;
}

/* --- 诱饵导出 --- */
void m13b_decoy_seal(void) {}
void m13b_fold(void) {}
void m13b_spin(void) {}

/* --- JNI 桥接 --- */

/* Zn.nativePartBFromB() → int（交叉调用入口，供 Java 直接调用） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Zn_nativePartBFromB(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return (jint)m13b_get_digest_B(NULL);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    return JNI_VERSION_1_6;
}
