#include <jni.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// 关卡 36：查表识君（手写 AES-128，真身沉底 + 指针表派发）
//   密钥藏法（不异或）：.rodata 里躺着一个 Base64 串——看着像乱码，其实
//   base64 解码回来就是 AES-128 钥匙（Base64 不是加密，教程 02 的老朋友）。
//   派生链：标记 Fatdog_break(UTF-16) → SHA256("|key")[:16] → Base64 存储。
//   协议：enc=hex(AES-ECB(key,"page=N&ts=T" 零填充))、sign=HMAC(mac,enc)，
//   mac=SHA256(Fatdog_break|"mac")。认算法靠魔数：S 盒开头 63 7c 77 7b。
// ============================================================================

/* 标记 "Fatdog_break"，UTF-16LE 码元（非 const 全局防折叠） */
unsigned short KEY36[] = {0x0046,0x0061,0x0074,0x0064,0x006f,0x0067,0x005f,
                          0x0062,0x0072,0x0065,0x0061,0x006b};

/* Base64 形态的钥匙：明文躺在 .rodata——它就是本关的"藏宝图" */
char K36_KEY_B64[] = "tE5zEyf1b+fe49uJN4cY7w==";

static unsigned char k36_aes_key[16];
static unsigned char k36_mac[32];
static unsigned char k36_master[12];

/* ---------------- 前半：无用变换函数群（诱饵垫底） ---------------- */

__attribute__((noinline)) int k36_fake_swap_pairs(unsigned char *p,int n){
    int i; for(i=0;i+1<n;i+=2){unsigned char t=p[i];p[i]=p[i+1];p[i+1]=t;} return n;
}
__attribute__((noinline)) int k36_fake_acc_mix(unsigned char *p,int n){
    unsigned char a=0x33; int i; for(i=0;i<n;i++){a=(unsigned char)(a*17+p[i]);p[i]^=a;} return a;
}
__attribute__((noinline)) int k36_fake_rev(unsigned char *p,int n){
    int i; for(i=0;i<n/2;i++){unsigned char t=p[i];p[i]=p[n-1-i];p[n-1-i]=t;} return n;
}

/* ---------------- Base64 解码（标准字母表） ---------------- */

static int k36_b64_val(char ch){
    if(ch>='A'&&ch<='Z') return ch-'A';
    if(ch>='a'&&ch<='z') return ch-'a'+26;
    if(ch>='0'&&ch<='9') return ch-'0'+52;
    if(ch=='+') return 62;
    if(ch=='/') return 63;
    return -1;
}
static int k36_b64_decode(const char *in, unsigned char *out){
    int v=0,bits=0,n=0,i;
    for(i=0;in[i];i++){
        int d=k36_b64_val(in[i]);
        if(d<0) continue;                     /* 跳过 '=' 等 */
        v=(v<<6)|d; bits+=6;
        if(bits>=8){ bits-=8; out[n++]=(unsigned char)((v>>bits)&0xFF); }
    }
    return n;
}

/* ---------------- SHA-256 / HMAC-SHA256（紧凑实现） ---------------- */
typedef struct {
    unsigned int h[8];
    unsigned char buf[64];
    unsigned long long total;
} sha256_ctx;

static const unsigned int K256[64] = {
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

static unsigned int rotr(unsigned int x,int n){return (x>>n)|(x<<(32-n));}

static void sha256_block(sha256_ctx *c,const unsigned char *p){
    unsigned int w[64]; int i;
    for(i=0;i<16;i++)
        w[i]=((unsigned int)p[i*4]<<24)|((unsigned int)p[i*4+1]<<16)|((unsigned int)p[i*4+2]<<8)|(unsigned int)p[i*4+3];
    for(i=16;i<64;i++){
        unsigned int s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
        unsigned int s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    {
        unsigned int a=c->h[0],b=c->h[1],cc=c->h[2],d=c->h[3];
        unsigned int e=c->h[4],f=c->h[5],g=c->h[6],h=c->h[7];
        for(i=0;i<64;i++){
            unsigned int S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
            unsigned int ch=(e&f)^((~e)&g);
            unsigned int t1=h+S1+ch+K256[i]+w[i];
            unsigned int S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
            unsigned int mj=(a&b)^(a&cc)^(b&cc);
            unsigned int t2=S0+mj;
            h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;
        }
        c->h[0]+=a;c->h[1]+=b;c->h[2]+=cc;c->h[3]+=d;
        c->h[4]+=e;c->h[5]+=f;c->h[6]+=g;c->h[7]+=h;
    }
}
static void sha256_init(sha256_ctx *c){
    c->h[0]=0x6a09e667u;c->h[1]=0xbb67ae85u;c->h[2]=0x3c6ef372u;c->h[3]=0xa54ff53au;
    c->h[4]=0x510e527fu;c->h[5]=0x9b05688cu;c->h[6]=0x1f83d9abu;c->h[7]=0x5be0cd19u;
    c->total=0;
}
static void sha256_update(sha256_ctx *c,const unsigned char *data,size_t len){
    size_t used,rem,i;
    c->total+=len;
    used=(size_t)((c->total-len)&63); rem=64-used;
    if(len>=rem){
        memcpy(c->buf+used,data,rem);
        sha256_block(c,c->buf);
        for(i=rem;i+64<=len;i+=64) sha256_block(c,data+i);
        data+=i; len-=i; used=0;
    }
    memcpy(c->buf+used,data,len);
}
static void sha256_final(sha256_ctx *c,unsigned char out[32]){
    unsigned long long bits=c->total*8;
    unsigned char pad[128];
    size_t used=(size_t)(c->total&63);
    size_t padlen=(used<56)?(56-used):(120-used);
    int i;
    memset(pad,0,sizeof(pad)); pad[0]=0x80;
    for(i=0;i<8;i++) pad[padlen+i]=(unsigned char)(bits>>(56-8*i));
    sha256_update(c,pad,padlen+8);
    for(i=0;i<8;i++){
        out[i*4]=(unsigned char)(c->h[i]>>24);
        out[i*4+1]=(unsigned char)(c->h[i]>>16);
        out[i*4+2]=(unsigned char)(c->h[i]>>8);
        out[i*4+3]=(unsigned char)(c->h[i]);
    }
}
static void hmac_sha256(const unsigned char *key,size_t klen,
                        const unsigned char *msg,size_t mlen,unsigned char out[32]){
    unsigned char k[64],ipad[64],opad[64],inner[32];
    sha256_ctx c; int i;
    memset(k,0,sizeof(k));
    if(klen>64){sha256_init(&c);sha256_update(&c,key,klen);sha256_final(&c,k);}
    else memcpy(k,key,klen);
    for(i=0;i<64;i++){ipad[i]=k[i]^0x36;opad[i]=k[i]^0x5c;}
    sha256_init(&c);sha256_update(&c,ipad,64);sha256_update(&c,msg,mlen);sha256_final(&c,inner);
    sha256_init(&c);sha256_update(&c,opad,64);sha256_update(&c,inner,32);sha256_final(&c,out);
}


static void k36_keys_init(void) {
    /* Base64 解码即得 AES 钥匙；MAC 钥匙运行时派生（种子不进 .rodata） */
    unsigned char seed[24];
    static const char t_mac[]={'|','m','a','c'};
    int i;
    k36_b64_decode(K36_KEY_B64, k36_aes_key);
    for(i=0;i<12;i++){ seed[i]=(char)(KEY36[i]&0xFF); k36_master[i]=(char)(KEY36[i]&0xFF); }
    memcpy(seed+12,t_mac,4);
    {
        sha256_ctx c; unsigned char d[32];
        sha256_init(&c); sha256_update(&c,seed,16); sha256_final(&c,d);
        memcpy(k36_mac,d,32);
    }
}


/* ================= 手写 AES-128（S 盒 63 7c 77 7b… 魔数认阵） ================= */

static const unsigned char K36_SBOX[256] = {
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
};

static const unsigned char K36_RCON[10][4] = {
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00,
        0x1b, 0x00, 0x00, 0x00,
        0x36, 0x00, 0x00, 0x00,
};

static unsigned char k36_xt(unsigned char v){ return (unsigned char)((v<<1)^((v>>7)*0x1B)); }

static void k36_expand(const unsigned char key[16], unsigned char rk[11][16]) {
    unsigned char w[44][4];
    int i,j;
    for(i=0;i<4;i++) for(j=0;j<4;j++) w[i][j]=key[i*4+j];
    for(i=4;i<44;i++){
        unsigned char t[4];
        memcpy(t,w[i-1],4);
        if(i%4==0){
            unsigned char first=t[0];
            t[0]=K36_SBOX[t[1]];t[1]=K36_SBOX[t[2]];t[2]=K36_SBOX[t[3]];t[3]=K36_SBOX[first];
            t[0]^=K36_RCON[i/4-1][0];
        }
        for(j=0;j<4;j++) w[i][j]=(unsigned char)(w[i-4][j]^t[j]);
    }
    for(i=0;i<11;i++) for(j=0;j<4;j++)
        memcpy(rk[i]+j*4,w[i*4+j],4);
}

/* 列主序 state：s[r][c] = blk[c*4+r] */
__attribute__((noinline)) static void k36_block(unsigned char blk[16], const unsigned char rk[11][16]) {
    unsigned char s[4][4];
    int r,c,rnd;
    for(c=0;c<4;c++) for(r=0;r<4;r++) s[r][c]=blk[c*4+r];

    for(c=0;c<4;c++) for(r=0;r<4;r++) s[r][c]^=rk[0][c*4+r];

    for(rnd=1;rnd<=9;rnd++){
        for(r=0;r<4;r++) for(c=0;c<4;c++) s[r][c]=K36_SBOX[s[r][c]];
        for(r=1;r<4;r++){
            unsigned char row[4];
            for(c=0;c<4;c++) row[c]=s[r][(c+r)%4];
            for(c=0;c<4;c++) s[r][c]=row[c];
        }
        for(c=0;c<4;c++){
            unsigned char a0=s[0][c],a1=s[1][c],a2=s[2][c],a3=s[3][c];
            s[0][c]=(unsigned char)(k36_xt(a0)^(k36_xt(a1)^a1)^a2^a3);
            s[1][c]=(unsigned char)(a0^k36_xt(a1)^(k36_xt(a2)^a2)^a3);
            s[2][c]=(unsigned char)(a0^a1^k36_xt(a2)^(k36_xt(a3)^a3));
            s[3][c]=(unsigned char)((k36_xt(a0)^a0)^a1^a2^k36_xt(a3));
        }
        for(c=0;c<4;c++) for(r=0;r<4;r++) s[r][c]^=rk[rnd][c*4+r];
    }

    for(r=0;r<4;r++) for(c=0;c<4;c++) s[r][c]=K36_SBOX[s[r][c]];
    for(r=1;r<4;r++){
        unsigned char row[4];
        for(c=0;c<4;c++) row[c]=s[r][(c+r)%4];
        for(c=0;c<4;c++) s[r][c]=row[c];
    }
    for(c=0;c<4;c++) for(r=0;r<4;r++) s[r][c]^=rk[10][c*4+r];

    for(c=0;c<4;c++) for(r=0;r<4;r++) blk[c*4+r]=s[r][c];
}

__attribute__((noinline)) static void k36_ecb(const unsigned char *in,size_t n,
                                              unsigned char out[64]) {
    unsigned char rk[11][16];
    size_t off;
    k36_expand(k36_aes_key,rk);
    for(off=0;off<n;off+=16){
        memcpy(out+off,in+off,16);
        k36_block(out+off,rk);
    }
}

/* ================= 底部：派发表 + JNI 入口 ================= */

typedef void (*k36_aes_fn)(const unsigned char *,size_t,unsigned char *);
static const k36_aes_fn K36_TBL[2]={ NULL, k36_ecb };
static volatile int K36_SLOT=1;

static void to_hex(const unsigned char *d,int n,char *hex){
    static const char h[]="0123456789abcdef";
    int i;
    for(i=0;i<n;i++){hex[i*2]=h[d[i]>>4];hex[i*2+1]=h[d[i]&0x0f];}
    hex[n*2]='\0';
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Mn_nativeEnc(JNIEnv *env,jclass clazz,jint page,jlong ts){
    char msg[64]; unsigned char buf[64],out[64]; char hex[129];
    int mlen,padded;
    (void)clazz;
    mlen=snprintf(msg,sizeof(msg),"page=%d&ts=%lld",(int)page,(long long)ts);
    padded=(mlen+15)/16*16;
    memset(buf,0,(size_t)padded);
    memcpy(buf,msg,(size_t)mlen);
    K36_TBL[K36_SLOT](buf,(size_t)padded,out);
    to_hex(out,padded,hex);
    return (*env)->NewStringUTF(env,hex);
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Mn_nativeSign(JNIEnv *env,jclass clazz,jstring encHex){
    const char *enc; unsigned char mac[32]; char hex[65];
    (void)clazz;
    enc=(*env)->GetStringUTFChars(env,encHex,NULL);
    if(enc==NULL) return (*env)->NewStringUTF(env,"");
    hmac_sha256(k36_mac,32,(const unsigned char *)enc,strlen(enc),mac);
    (*env)->ReleaseStringUTFChars(env,encHex,enc);
    to_hex(mac,32,hex);
    return (*env)->NewStringUTF(env,hex);
}
