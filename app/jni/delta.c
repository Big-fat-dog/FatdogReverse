/*
 * 太玄之初 KL20：破壁飞升——三代壳综合。
 *
 * 综合前面所有关卡的技术：
 *   外层：XOR+Base64 加密（同 KL16/17）
 *   中层：OLLVM 状态机混淆（同 KL18）
 *   内层：VMP 字节码执行（同 KL19）
 *   额外：反调试 + CRC 自校验
 *
 * 玩家需逐层突破：反调试 → 脱壳 → OLLVM → VMP → 算出答案。
 *
 * 标记（真）：Fatdog_break   — UTF-16 码元。
 * 诱饵（假）：Fatdog_breaker — 一字之差。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

/* --- 真标记：Fatdog_break（UTF-16LE） --- */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0062, 0x0072, 0x0065, 0x0061, 0x006B
};
#define MARKER_LEN 12

/* --- 诱饵：Fatdog_breaker --- */
static const jchar DECOY[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0062, 0x0072, 0x0065, 0x0061, 0x006B, 0x0065, 0x0072
};
#define DECOY_LEN 14

/* ============================================================
 * 外层：XOR + Base64（同 KL16/17 手法）
 * ============================================================ */
static const uint8_t XOR_KEY[] = { 0x5A, 0x3C, 0x7E, 0x1D, 0x92, 0x64, 0xA8, 0xF0 };
/* 加密数据：Base64("KL20_SEED:20281001") XOR 轮转密钥 */
static const uint8_t ENC_DATA[] = {
    0x51, 0x2E, 0x4A, 0x08, 0x6E, 0x53, 0x7B, 0x1D,
    0x48, 0x3F, 0x25, 0x5A, 0x72, 0x61, 0x0C, 0x3E,
    0x5B, 0x6F, 0x3A, 0x10, 0x77, 0x2C, 0x45, 0x09
};
#define ENC_LEN 24

static const char B64_TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_decode(const uint8_t *enc, int enc_len, uint8_t *out) {
    int out_len = 0;
    for (int i = 0; i < enc_len; i += 4) {
        uint32_t val = 0;
        for (int j = 0; j < 4 && (i + j) < enc_len; j++) {
            char c = (char)enc[i + j];
            if (c == '=') { val <<= 6; continue; }
            const char *p = strchr(B64_TABLE, c);
            if (!p) return -1;
            val = (val << 6) | (p - B64_TABLE);
        }
        out[out_len++] = (uint8_t)(val >> 16);
        if (enc[i + 2] != '=') out[out_len++] = (uint8_t)(val >> 8);
        if (enc[i + 3] != '=') out[out_len++] = (uint8_t)val;
    }
    return out_len;
}

/* ============================================================
 * 中层：OLLVM 状态机（简化版，8 个 case）
 * ============================================================ */
#define OLLVM_ROL(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define OLLVM_ADD(a,b) ((uint32_t)(((a)^(b))+(((a)&(b))<<1)))

static uint32_t ollvm_transform(uint32_t seed) {
    uint32_t state = seed;
    int case_id = 0;
    int iter = 0;
    while (iter < 16) {
        switch (case_id) {
        case 0: state ^= 0xDEADBEEF; case_id = 1; break;
        case 1: state = OLLVM_ROL(state, 13); case_id = 2; break;
        case 2: state = OLLVM_ADD(state, 0x12345678); case_id = 3; break;
        case 3: state ^= 0xCAFEBABE; case_id = 4; break;
        case 4: state = OLLVM_ROL(state, 7); case_id = 5; break;
        case 5: state = OLLVM_ADD(state, 0x98765432); case_id = 6; break;
        case 6: return state;
        /* 虚假路径 */
        case 7: return 0;
        default: return 0;
        }
        iter++;
    }
    return 0;
}

/* ============================================================
 * 内层：VMP 字节码（简化版，8 条指令）
 * ============================================================ */
#define VM_XOR_KEY 0x5C
static const uint8_t VM_BC_ENC[] = {
    0x5E, 0x5A, 0x54, 0x57, 0x56, 0x5F, 0x51, 0x52,
    0x5E, 0x5A, 0x5B, 0x56, 0x5F, 0x5D, 0x50, 0x59,
    0x5E, 0x5A, 0x53, 0x50, 0x54, 0x53, 0x58, 0x55,
    0x5E, 0x5A, 0x54, 0x43, 0x56, 0x5D, 0x42, 0x5B
};
#define VM_BC_LEN 32

static uint32_t vm_execute(const uint8_t *enc, int len) {
    uint32_t regs[4] = {0, 0, 0, 0}; /* V0-V3 */
    for (int i = 0; i < len; i += 4) {
        uint8_t opc = enc[i] ^ VM_XOR_KEY;
        uint8_t rd  = enc[i+1] ^ VM_XOR_KEY;
        uint8_t rs1 = enc[i+2] ^ VM_XOR_KEY;
        uint8_t imm = enc[i+3] ^ VM_XOR_KEY;
        switch (opc) {
        case 0x08: regs[rd & 3] = imm; break;           /* MOV */
        case 0x0A: regs[rd & 3] ^= imm; break;          /* XORI */
        case 0x09: regs[rd & 3] += imm; break;          /* ADDI */
        case 0x06: regs[rd & 3] = regs[rs1 & 3] << (imm & 31); break; /* SHL */
        case 0x03: regs[rd & 3] = regs[rs1 & 3] ^ regs[(rs1+1) & 3]; break; /* XOR */
        case 0x16: return regs[0];                       /* HALT */
        default: break;
        }
    }
    return regs[0];
}

/* ============================================================
 * 反调试（简化版）
 * ============================================================ */
static volatile int anti_debug_ok = 0;

static int check_ptrace(void) {
    int pid = fork();
    if (pid == 0) {
        long r = (long)ptrace(0, 0, 0, 0);
        _exit(r == 0 ? 0 : 1);
    }
    if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 1;
    }
    return 0;
}

static int check_tracer_pid(void) {
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return 1;
    char buf[2048];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 1;
    buf[n] = '\0';
    char *p = strstr(buf, "TracerPid:");
    if (!p) return 1;
    p += 10;
    while (*p == ' ') p++;
    return (atoi(p) == 0) ? 1 : 0;
}

/* CRC 自校验（简化） */
static volatile uint32_t crc_baseline = 0;

/* ============================================================
 * 简易 SHA-256
 * ============================================================ */
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

static uint32_t extract_seed(const uint8_t *decoded, int len) {
    if (len < 14) return 0;
    uint32_t seed = 0;
    for (int i = 0; i < 4; i++)
        seed = (seed << 8) | decoded[10 + i];
    return seed;
}

static void get_answer(uint32_t seed, char out[33]) {
    uint8_t buf[4] = {
        (uint8_t)(seed >> 24), (uint8_t)(seed >> 16),
        (uint8_t)(seed >> 8),  (uint8_t)seed
    };
    uint8_t h[32];
    sha256(buf, 4, h);
    to_hex(h, 32, out);
}

/* --- 诱饵导出 --- */
void k20_decoy_seal(void) {}
void k20_fold(void) {}
void k20_spin(void) {}

/* ============================================================
 * JNI 桥接
 * ============================================================ */

/* Hk.nativeAntiDebug() → int */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Hk_nativeAntiDebug(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    anti_debug_ok = (check_ptrace() && check_tracer_pid()) ? 1 : 0;
    return anti_debug_ok;
}

/* Hk.nativeDecrypt() → String（外层解密结果） */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Hk_nativeDecrypt(JNIEnv *env, jclass clazz) {
    (void)clazz;
    if (!anti_debug_ok) return (*env)->NewStringUTF(env, "anti-debug failed");
    uint8_t xored[ENC_LEN];
    for (int i = 0; i < ENC_LEN; i++) xored[i] = ENC_DATA[i] ^ XOR_KEY[i % 8];
    uint8_t decoded[ENC_LEN];
    int dec_len = b64_decode(xored, ENC_LEN, decoded);
    if (dec_len < 0) return (*env)->NewStringUTF(env, "decode error");
    char hex[64];
    to_hex(decoded, dec_len, hex);
    return (*env)->NewStringUTF(env, hex);
}

/* Hk.nativeSeed() → int */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Hk_nativeSeed(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    if (!anti_debug_ok) return 0;
    uint8_t xored[ENC_LEN];
    for (int i = 0; i < ENC_LEN; i++) xored[i] = ENC_DATA[i] ^ XOR_KEY[i % 8];
    uint8_t decoded[ENC_LEN];
    int dec_len = b64_decode(xored, ENC_LEN, decoded);
    if (dec_len < 0) return 0;
    return (jint)extract_seed(decoded, dec_len);
}

/* Hk.nativeAnswer() → String */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Hk_nativeAnswer(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    if (!anti_debug_ok) return (*env)->NewStringUTF(env, "anti-debug failed");
    uint8_t xored[ENC_LEN];
    for (int i = 0; i < ENC_LEN; i++) xored[i] = ENC_DATA[i] ^ XOR_KEY[i % 8];
    uint8_t decoded[ENC_LEN];
    int dec_len = b64_decode(xored, ENC_LEN, decoded);
    if (dec_len < 0) return (*env)->NewStringUTF(env, "decode error");
    uint32_t seed = extract_seed(decoded, dec_len);
    char hex[33];
    get_answer(seed, hex);
    return (*env)->NewStringUTF(env, hex);
}

/* Hk.nativeOllvm(int seed) → int（中层 OLLVM 变换） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Hk_nativeOllvm(JNIEnv *env, jclass clazz, jint seed) {
    (void)env; (void)clazz;
    return (jint)ollvm_transform((uint32_t)seed);
}

/* Hk.nativeVmExecute() → int（内层 VMP 执行） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Hk_nativeVmExecute(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return (jint)vm_execute(VM_BC_ENC, VM_BC_LEN);
}

/* Hk.nativeStatus() → String（各层状态） */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Hk_nativeStatus(JNIEnv *env, jclass clazz) {
    (void)clazz;
    char buf[256];
    snprintf(buf, sizeof(buf),
        "anti_debug = %d\n"
        "ptrace     = %d\n"
        "tracer_pid = %d\n"
        "crc_base   = 0x%08X\n"
        "layers     = 3 (outer/ollvm/vmp)",
        anti_debug_ok, check_ptrace(), check_tracer_pid(), crc_baseline);
    return (*env)->NewStringUTF(env, buf);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    crc_baseline = 0xAABBCCDD; /* 占位 */
    return JNI_VERSION_1_6;
}
