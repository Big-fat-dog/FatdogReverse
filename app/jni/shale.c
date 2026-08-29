/*
 * 幽冥海 KL15：万法归宗——综合收官卷（多阶段谜题）。
 *
 * 与前几关不同：不是简单的 guard→answer，而是三阶段递进谜题。
 *   阶段 A：computeA() → 返回种子值（XOR + 移位）
 *   阶段 B：computeB(a) → 基于 A 的值做进一步变换（CRC 衍生）
 *   阶段 C：computeC(a, b) → 组合 A+B 做 SHA-256 得最终值
 *   验证：verify(a, b, c) → 三值全对才返回 1
 *
 * 每阶段逻辑不同：A 用 XOR+移位，B 用 CRC 衍生，C 用 SHA-256。
 * 单独 hook 任一函数拿到的值不完整，必须三阶段全过。
 *
 * 标记（真）：Fatdog_pact  — UTF-16 码元。
 * 诱饵（假）：Fatdog_packed — 一字之差。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>

/* --- 真标记：Fatdog_pact（UTF-16LE 码元） --- */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0070, 0x0061, 0x0063, 0x0074
};
#define MARKER_LEN 11

/* --- 诱饵：Fatdog_packed --- */
static const jchar DECOY[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0070, 0x0061, 0x0063, 0x006B, 0x0065, 0x0064
};
#define DECOY_LEN 13

/* --- 常量 --- */
#define SEED  20280426
#define MAGIC 0xDEADCAFE
#define XOR_K 0x0000BEEF

/* --- 密钥异或 --- */
static const uint8_t KX[] = {0x5E, 0x3A, 0x7D, 0x1F, 0x92, 0x64, 0xA8, 0xC0};

/* --- SHA-256 --- */
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

/* --- CRC32 --- */
static uint32_t crc32(const uint8_t *d, int l){
    uint32_t c=0xFFFFFFFF; int i,j;
    for(i=0;i<l;i++){c^=(uint32_t)d[i];for(j=0;j<8;j++)c=(c&1)?((c>>1)^0xEDB88320):(c>>1);}
    return c^0xFFFFFFFF;
}

/* --- 反调试 --- */
static int anti_debug(void){
    return (ptrace(PTRACE_TRACEME,0,0,0)!=-1)?1:0;
}

/* --- CRC 校验 --- */
static uint32_t crc_base=0;
static void init_crc(void){
    uint8_t buf[64]; int o=0; uint32_t v;
    memcpy(buf,MARKER,sizeof(MARKER)); o+=sizeof(MARKER);
    v=MAGIC; memcpy(buf+o,&v,4); o+=4;
    v=XOR_K; memcpy(buf+o,&v,4); o+=4;
    v=SEED;  memcpy(buf+o,&v,4); o+=4;
    memcpy(buf+o,KX,8); o+=8;
    crc_base=crc32(buf,o);
}
static int chk_crc(void){
    uint8_t buf[64]; int o=0; uint32_t v;
    memcpy(buf,MARKER,sizeof(MARKER)); o+=sizeof(MARKER);
    v=MAGIC; memcpy(buf+o,&v,4); o+=4;
    v=XOR_K; memcpy(buf+o,&v,4); o+=4;
    v=SEED;  memcpy(buf+o,&v,4); o+=4;
    memcpy(buf+o,KX,8); o+=8;
    return crc32(buf,o)==crc_base;
}

/*
 * 三阶段计算：
 *   A = XOR(SEED, MAGIC) + 移位 + 密钥异或
 *   B = CRC32(A 的字节) 再异或 KX
 *   C = SHA256(A‖B) 取前 8 字节
 * verify(a,b,c)：重算一遍比对。
 */

/* 阶段 A：XOR + 移位 + 密钥异或 */
static uint32_t calc_a(void){
    uint32_t v=(uint32_t)(SEED^MAGIC);
    v=(v<<13)|(v>>19);
    v^=XOR_K;
    v=v*0x9E3779B9u+0x12345678u;
    uint8_t *p=(uint8_t*)&v;
    for(int i=0;i<4;i++) p[i]^=KX[i];
    return v;
}

/* 阶段 B：CRC32(a) 衍生 + KX 混淆 */
static uint32_t calc_b(uint32_t a){
    uint8_t buf[4];
    buf[0]=(uint8_t)(a>>24); buf[1]=(uint8_t)(a>>16);
    buf[2]=(uint8_t)(a>>8);  buf[3]=(uint8_t)a;
    uint32_t h=crc32(buf,4);
    h^=(uint32_t)(KX[0]|(KX[1]<<8)|(KX[2]<<16)|(KX[3]<<24));
    return h;
}

/* 阶段 C：SHA256(a‖b) 取前 8 字节 */
static uint32_t calc_c(uint32_t a, uint32_t b){
    uint8_t buf[8], h[32];
    buf[0]=(uint8_t)(a>>24); buf[1]=(uint8_t)(a>>16);
    buf[2]=(uint8_t)(a>>8);  buf[3]=(uint8_t)a;
    buf[4]=(uint8_t)(b>>24); buf[5]=(uint8_t)(b>>16);
    buf[6]=(uint8_t)(b>>8);  buf[7]=(uint8_t)b;
    sha256(buf,8,h);
    uint32_t r;
    r=((uint32_t)h[0]<<24)|((uint32_t)h[1]<<16)|((uint32_t)h[2]<<8)|(uint32_t)h[3];
    return r;
}

/* 验证：三值全对返回 1 */
static int do_verify(uint32_t a, uint32_t b, uint32_t c){
    return (a==calc_a() && b==calc_b(a) && c==calc_c(a,b))?1:0;
}

/* --- 诱饵导出 --- */
void m14_decoy_seal(void){}
void m14_fold(void){}
void m14_spin(void){}

/* --- JNI 桥接 --- */

/* Am.nativeGuard(input) → int（兼容旧接口：反调试+CRC+综合校验） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Am_nativeGuard(JNIEnv *env, jclass clazz, jint input){
    (void)env;(void)clazz;
    static int inited=0;
    if(!inited){init_crc();inited=1;}
    if(!anti_debug()) return -1;
    if(!chk_crc()) return -2;
    (void)input;
    return 1;
}

/* Am.nativeComputeA() → int（阶段 A） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Am_nativeComputeA(JNIEnv *env, jclass clazz){
    (void)env;(void)clazz;
    static int inited=0;
    if(!inited){init_crc();inited=1;}
    return (jint)calc_a();
}

/* Am.nativeComputeB(int a) → int（阶段 B） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Am_nativeComputeB(JNIEnv *env, jclass clazz, jint a){
    (void)env;(void)clazz;
    return (jint)calc_b((uint32_t)a);
}

/* Am.nativeComputeC(int a, int b) → int（阶段 C） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Am_nativeComputeC(JNIEnv *env, jclass clazz, jint a, jint b){
    (void)env;(void)clazz;
    return (jint)calc_c((uint32_t)a,(uint32_t)b);
}

/* Am.nativeVerify(int a, int b, int c) → int（验证三值） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Am_nativeVerify(JNIEnv *env, jclass clazz, jint a, jint b, jint c){
    (void)env;(void)clazz;
    static int inited=0;
    if(!inited){init_crc();inited=1;}
    return (jint)do_verify((uint32_t)a,(uint32_t)b,(uint32_t)c);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved){
    (void)vm;(void)reserved;
    return JNI_VERSION_1_6;
}
