#include <jni.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// 关卡 37：雪崩之谜（native 第三季）
//   手写 SHA-256 变体 + RC4 叠加：
//     d    = SHA256变体(payload)      —— K 表/压缩轮与标准一致，但 IV 整组
//            换成 SHA256("Fatdog_dodge|iv") 派生值 → hashlib 直接对不上
//     sign = hex( RC4(SHA256("Fatdog_dodge|rc4")[:16], d) )   → 再裹一层流密码
//   认骨架靠 K 表（428a2f98…），找改动点看初始化：h[] 不再是教科书常量。
//   前半文件依旧是无用变换函数垫底，真身沉底经指针表派发。
// ============================================================================

/* 标记 "Fatdog_dodge"，UTF-16LE 码元（非 const 全局防折叠） */
unsigned short KEY37[] = {0x0046,0x0061,0x0074,0x0064,0x006f,0x0067,0x005f,
                          0x0064,0x006f,0x0064,0x0067,0x0065};

static unsigned char k37_iv[32];
static unsigned char k37_rc4key[16];
static unsigned char k37_master[12];

/* ---------------- 前半：无用变换函数群（诱饵垫底） ---------------- */

__attribute__((noinline)) int k37_fake_fold(unsigned char *p,int n){
    int i; for(i=0;i+2<n;i+=3){unsigned char t=p[i];p[i]=p[i+2];p[i+2]=t;} return n;
}
__attribute__((noinline)) int k37_fake_wobble(unsigned char *p,int n){
    int i; for(i=1;i<n;i++) p[i]=(unsigned char)(p[i]+p[i-1]); return p[0];
}
__attribute__((noinline)) int k37_junk_stretch(unsigned char *p,int n,int w){
    while(n<w) p[n++]=0x5D; return n;
}

/* ---------------- SHA-256（压缩逻辑与标准一致；IV 可换） ---------------- */

static const unsigned int K37_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

/* 变体的灵魂：IV 不是教科书那组常量，而是派生值（k37_keys_init 里填） */
static const unsigned int K37_STD_IV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};
static unsigned int K37_IV[8];

static unsigned int k37_rotr(unsigned int x,int n){ return (x>>n)|(x<<(32-n)); }

static void k37_sha_block(unsigned int h[8], const unsigned char *p) {
    unsigned int w[64];
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[i*4]<<24)|((unsigned int)p[i*4+1]<<16)
             | ((unsigned int)p[i*4+2]<<8)|(unsigned int)p[i*4+3];
    for (i = 16; i < 64; i++) {
        unsigned int s0=k37_rotr(w[i-15],7)^k37_rotr(w[i-15],18)^(w[i-15]>>3);
        unsigned int s1=k37_rotr(w[i-2],17)^k37_rotr(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    {
        unsigned int a=h[0],b=h[1],c=h[2],d=h[3];
        unsigned int e=h[4],f=h[5],g=h[6],hh=h[7];
        for(i=0;i<64;i++){
            unsigned int S1=k37_rotr(e,6)^k37_rotr(e,11)^k37_rotr(e,25);
            unsigned int ch=(e&f)^((~e)&g);
            unsigned int t1=hh+S1+ch+K37_K[i]+w[i];
            unsigned int S0=k37_rotr(a,2)^k37_rotr(a,13)^k37_rotr(a,22);
            unsigned int mj=(a&b)^(a&c)^(b&c);
            unsigned int t2=S0+mj;
            unsigned int ne=d+t1;
            hh=g;g=f;f=e;e=ne;
            d=c;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;
        h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
}

/* data 长度需为 64 的倍数（调用方先做填充），逐块压缩后输出 32 字节 */
static void k37_sha(const unsigned char *data, size_t blocks, unsigned char out[32]) {
    unsigned int h[8];
    int i,j;
    for(i=0;i<8;i++) h[i]=K37_IV[i];
    for(j=0;(size_t)j<blocks;j++) {
        k37_sha_block(h,data+(size_t)j*64);
    }
    for(i=0;i<8;i++){
        out[i*4]  =(unsigned char)(h[i]>>24);
        out[i*4+1]=(unsigned char)(h[i]>>16);
        out[i*4+2]=(unsigned char)(h[i]>>8);
        out[i*4+3]=(unsigned char)(h[i]);
    }
}

/* 标准 SHA-256（用教科书 IV），仅用于派生 IV/RC4 钥匙 */
static void k37_std_sha(const unsigned char *data,size_t len,unsigned char out[32]) {
    /* 复用同一压缩函数：先把标准 IV 装入，再走完整填充流程 */
    unsigned char buf[128];
    size_t total=len,i;
    unsigned int h[8];
    unsigned long long bits=(unsigned long long)len*8;
    unsigned char pad[128];
    size_t used=len%64, padlen=(used<56)?(56-used):(120-used);
    for(i=0;i<8;i++) h[i]=K37_STD_IV[i];
    if(len>64){ /* 本项目种子都很短，超长分支不会走到；防御性截断 */ len=64; }
    memcpy(buf,data,len);
    memset(pad,0,sizeof(pad)); pad[0]=0x80;
    for(i=0;i<8;i++) pad[padlen+i]=(unsigned char)(bits>>(56-8*i));
    /* 短消息单块即可（len<=55 时）；否则两块 */
    {
        unsigned char chunk[128];
        size_t clen=used+padlen+8;
        memcpy(chunk,buf,used); memcpy(chunk+used,pad,padlen+8);
        for(i=0;i<(int)(clen/64);i++) k37_sha_block(h,chunk+(size_t)i*64);
    }
    for(i=0;i<8;i++){
        out[i*4]=(unsigned char)(h[i]>>24);
        out[i*4+1]=(unsigned char)(h[i]>>16);
        out[i*4+2]=(unsigned char)(h[i]>>8);
        out[i*4+3]=(unsigned char)(h[i]);
    }
    (void)total;
}

/* ---------------- RC4 ---------------- */

static void k37_rc4(const unsigned char *key,size_t klen,
                    const unsigned char *in,size_t n,unsigned char *out){
    unsigned char S[256],t;
    int i,j=0,a=0,b=0;
    size_t k;
    for(i=0;i<256;i++)S[i]=(unsigned char)i;
    for(i=0;i<256;i++){
        j=(j+S[i]+key[i%klen])&0xFF;
        t=S[i];S[i]=S[j];S[j]=t;
    }
    for(k=0;k<n;k++){
        a=(a+1)&0xFF; b=(b+S[a])&0xFF;
        t=S[a];S[a]=S[b];S[b]=t;
        out[k]=in[k]^S[(S[a]+S[b])&0xFF];
    }
}

static void to_hex(const unsigned char *d,int n,char *hex){
    static const char h[]="0123456789abcdef";
    int i;
    for(i=0;i<n;i++){hex[i*2]=h[d[i]>>4];hex[i*2+1]=h[d[i]&0x0f];}
    hex[n*2]='\0';
}

/* ---------------- 底部：真身实现 + 指针表派发 ---------------- */

__attribute__((noinline)) static void k37_variant_sign(JNIEnv *env,jint page,jlong ts,
                                                       char hex[65]) {
    char msg[64];
    unsigned char padded[64],dg[32],out[32];
    int mlen,padded_n;
    (void) env;
    mlen=snprintf(msg,sizeof(msg),"page=%d&ts=%lld",(int)page,(long long)ts);
    padded_n=(mlen+63)/64*64;
    memset(padded,0,(size_t)padded_n);
    memcpy(padded,msg,(size_t)mlen);
    k37_sha(padded,(size_t)(padded_n/64),dg);
    k37_rc4(k37_rc4key,16,dg,32,out);
    to_hex(out,32,hex);
}

typedef void (*k37_sign_fn)(JNIEnv *,jint,jlong,char[65]);
static const k37_sign_fn K37_TBL[2]={ NULL,k37_variant_sign };
static volatile int K37_SLOT=1;

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Qa_nativeSign(JNIEnv *env,jclass clazz,jint page,jlong ts){
    char hex[65];
    (void)clazz;
    K37_TBL[K37_SLOT](env,page,ts,hex);
    return (*env)->NewStringUTF(env,hex);
}

/* ---------------- 初始化：派生 IV / RC4 钥匙 ---------------- */

static void k37_keys_init(void) {
    unsigned char seed[24];
    static const char t_iv[]={'|','i','v'};
    static const char t_rc[]={'|','r','c','4'};
    int i;
    for(i=0;i<12;i++){seed[i]=(char)(KEY37[i]&0xFF);k37_master[i]=(char)(KEY37[i]&0xFF);}
    memcpy(seed+12,t_iv,3);
    k37_std_sha(seed,15,k37_iv);
    memcpy(seed+12,t_rc,4);
    k37_std_sha(seed,16,k37_rc4key);
    for(i=0;i<8;i++)
        K37_IV[i]=((unsigned int)k37_iv[i*4]<<24)|((unsigned int)k37_iv[i*4+1]<<16)
                |((unsigned int)k37_iv[i*4+2]<<8)|(unsigned int)k37_iv[i*4+3];
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    (void) reserved;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    k37_keys_init();                         /* 派生换血 IV 与 RC4 钥匙 */
    return JNI_VERSION_1_6;
}
