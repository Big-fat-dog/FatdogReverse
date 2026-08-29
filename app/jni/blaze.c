/*
 * 太玄之初 KL18：乾坤迷阵——OLLVM 控制流平坦化。
 *
 * 模拟 OLLVM 保护：核心算法被 switch-case 状态机平坦化，
 * 16 个 case 中 12 个是真实路径、4 个是虚假路径（死循环/提前退出）。
 * 指令替换：a+b → (a^b)+((a&b)<<1)
 * 字符串运行时逐字节 XOR 解密。
 *
 * 原始算法（玩家需还原）：
 *   state = seed
 *   state = (state ^ 0xA3B5C7D9) <<< 7
 *   state = state + 0x12345678
 *   state = state ^ 0x98765432
 *   最终 state 与 MAGIC 比较
 *
 * 玩家需：① 识别状态机结构 → ② 标记真实/虚假 case → ③ 还原原始算法。
 *
 * 标记（真）：Fatdog_unfold  — UTF-16 码元。
 * 诱饵（假）：Fatdog_folder  — 一字之差。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>

/* --- 真标记：Fatdog_unfold（UTF-16LE） --- */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0075, 0x006E, 0x0066, 0x006F, 0x006C, 0x0064
};
#define MARKER_LEN 13

/* --- 诱饵：Fatdog_folder --- */
static const jchar DECOY[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0066, 0x006F, 0x006C, 0x0064, 0x0065, 0x0072
};
#define DECOY_LEN 13

/* --- 常量 --- */
#define XOR_CONST1  0xA3B5C7D9u
#define ADD_CONST   0x12345678u
#define XOR_CONST2  0x98765432u
#define MAGIC       0xC47A2B1Eu

/* --- 指令替换宏（模拟 OLLVM 指令替换） --- */
/* a + b → (a ^ b) + ((a & b) << 1) */
#define OLLVM_ADD(a, b)  ((uint32_t)(((a) ^ (b)) + (((a) & (b)) << 1)))

/* --- 循环左移 --- */
#define ROL32(x, n)  (((x) << (n)) | ((x) >> (32 - (n))))

/* --- 加密数据 --- */
/* 明文 = "KL18_SEED:20280915"（19 bytes） */
/* 加密 = 逐字节 XOR 0x5C */
static const uint8_t ENC_DATA[] = {
    0x2E, 0x30, 0x27, 0x26, 0x21, 0x6E, 0x27, 0x30,
    0x6A, 0x31, 0x37, 0x21, 0x22, 0x73, 0x74, 0x79,
    0x31, 0x27, 0x26
};
#define ENC_LEN 19
#define ENC_XOR_KEY 0x5C

/* --- 状态机 case 编号（真实路径） --- */
/* 原始算法拆成 8 步，每步对应一个 case */
#define S_INIT      0
#define S_XOR1      1
#define S_ROL       2
#define S_ADD       3
#define S_XOR2      4
#define S_CHECK     5
#define S_DONE      6
#define S_ERROR     7
/* 虚假路径：8-11 */
#define S_FAKE1     8
#define S_FAKE2     9
#define S_FAKE3     10
#define S_FAKE4     11
/* 更多虚假：12-15 */
#define S_FAKE5     12
#define S_FAKE6     13
#define S_FAKE7     14
#define S_FAKE8     15

/*
 * 核心算法（被 OLLVM 平坦化前的原始逻辑）：
 * 输入 seed，经过变换后与 MAGIC 比较。
 */
static uint32_t core_algorithm(uint32_t seed) {
    uint32_t state = seed;
    state = ROL32(state ^ XOR_CONST1, 7);
    state = OLLVM_ADD(state, ADD_CONST);
    state = state ^ XOR_CONST2;
    return state;
}

/*
 * OLLVM 风格状态机：switch-case 平坦化。
 * 虚假路径会提前返回错误值或进入死循环。
 * 真实路径最终返回 core_algorithm(seed) 的结果。
 */
static uint32_t ollvm_state_machine(uint32_t seed) {
    uint32_t state = 0;
    int case_id = S_INIT;
    int iterations = 0;

    while (iterations < 32) { /* 防止虚假路径死循环 */
        switch (case_id) {
        /* === 真实路径 === */
        case S_INIT:
            state = seed;
            case_id = S_XOR1;
            break;

        case S_XOR1:
            state = state ^ XOR_CONST1;
            case_id = S_ROL;
            break;

        case S_ROL:
            state = ROL32(state, 7);
            case_id = S_ADD;
            break;

        case S_ADD:
            state = OLLVM_ADD(state, ADD_CONST);
            case_id = S_XOR2;
            break;

        case S_XOR2:
            state = state ^ XOR_CONST2;
            case_id = S_CHECK;
            break;

        case S_CHECK:
            /* 验证中间值是否合理（非零） */
            if (state != 0) {
                case_id = S_DONE;
            } else {
                case_id = S_ERROR;
            }
            break;

        case S_DONE:
            return state;

        case S_ERROR:
            return 0;

        /* === 虚假路径（混淆用） === */
        case S_FAKE1:
            state = seed ^ 0xDEADBEEF;
            return 0; /* 提前退出 */

        case S_FAKE2:
            state = ~seed;
            case_id = S_FAKE5; /* 跳到另一个虚假 */
            break;

        case S_FAKE3:
            state = seed + 1;
            return 0;

        case S_FAKE4:
            state = seed << 1;
            case_id = S_FAKE6;
            break;

        case S_FAKE5:
            state = state ^ 0xCAFEBABE;
            return 0;

        case S_FAKE6:
            state = state >> 1;
            return 0;

        case S_FAKE7:
            state = seed * 3;
            return 0;

        case S_FAKE8:
            state = seed - 1;
            return 0;

        default:
            return 0;
        }
        iterations++;
    }
    return 0;
}

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

/* --- 字符串运行时解密（模拟 OLLVM 字符串加密） --- */
static void decrypt_string(char *out, const uint8_t *enc, int len) {
    for (int i = 0; i < len; i++) {
        out[i] = (char)(enc[i] ^ ENC_XOR_KEY);
    }
    out[len] = '\0';
}

/* --- 提取种子 --- */
static uint32_t extract_seed(const uint8_t *dec, int len) {
    /* 明文格式 "KL18_SEED:XXXXXXXX"，跳过前 10 字节取 4 字节 */
    if (len < 14) return 0;
    uint32_t seed = 0;
    for (int i = 0; i < 4; i++) {
        seed = (seed << 8) | dec[10 + i];
    }
    return seed;
}

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
void k18_decoy_seal(void) {}
void k18_fold(void) {}
void k18_spin(void) {}

/* --- JNI 桥接 --- */

/* Fk.nativeDecrypt() → String（解密后的明文） */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Fk_nativeDecrypt(JNIEnv *env, jclass clazz) {
    (void)clazz;
    char dec[64];
    decrypt_string(dec, ENC_DATA, ENC_LEN);
    return (*env)->NewStringUTF(env, dec);
}

/* Fk.nativeSeed() → int（提取的种子值） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Fk_nativeSeed(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    uint8_t dec[64];
    for (int i = 0; i < ENC_LEN; i++) dec[i] = ENC_DATA[i] ^ ENC_XOR_KEY;
    return (jint)extract_seed(dec, ENC_LEN);
}

/* Fk.nativeAnswer() → String（最终答案 hex） */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Fk_nativeAnswer(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    uint8_t dec[64];
    for (int i = 0; i < ENC_LEN; i++) dec[i] = ENC_DATA[i] ^ ENC_XOR_KEY;
    uint32_t seed = extract_seed(dec, ENC_LEN);
    char hex[33];
    get_answer(seed, hex);
    return (*env)->NewStringUTF(env, hex);
}

/* Fk.nativeOllvm(uint32_t seed) → uint32_t
 * 暴露状态机函数，供玩家分析状态流转。
 * 返回状态机结果。
 */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Fk_nativeOllvm(JNIEnv *env, jclass clazz, jint seed) {
    (void)env; (void)clazz;
    return (jint)ollvm_state_machine((uint32_t)seed);
}

/* Fk.nativeCore(uint32_t seed) → uint32_t
 * 暴露核心算法（去除状态机），供玩家对拍验证。
 */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Fk_nativeCore(JNIEnv *env, jclass clazz, jint seed) {
    (void)env; (void)clazz;
    return (jint)core_algorithm((uint32_t)seed);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    return JNI_VERSION_1_6;
}
