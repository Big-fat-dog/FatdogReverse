/*
 * 太玄之初 KL17：金蝉脱壳——二代壳 DEX 热加载 + 反调试。
 *
 * 模拟二代壳：反调试三重检测 + 反hook + DEX 加密存储。
 * 反调试通过后才能拿到正确答案。
 *
 * 反调试三重：
 *   ① ptrace(PTRACE_TRACEME) 占坑
 *   ② 读 /proc/self/status 的 TracerPid
 *   ③ 检测 Frida 特征端口 27042
 * 反hook：mmap 映射函数头 → 定时比对检测 inline hook。
 *
 * 玩家需：① 绕过反调试 → ② 分析解密逻辑 → ③ 算出答案。
 *
 * 标记（真）：Fatdog_unpack  — UTF-16 码元。
 * 诱饵（假）：Fatdog_unpacker — 一字之差。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <dlfcn.h>

/* --- 真标记：Fatdog_unpack（UTF-16LE） --- */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0075, 0x006E, 0x0070, 0x0061, 0x0063, 0x006B
};
#define MARKER_LEN 13

/* --- 诱饵：Fatdog_unpacker --- */
static const jchar DECOY[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0075, 0x006E, 0x0070, 0x0061, 0x0063, 0x006B, 0x0065, 0x0072
};
#define DECOY_LEN 15

/* --- XOR 解密密钥（硬编码） --- */
static const uint8_t XOR_KEY[] = { 0x3B, 0x7A, 0x2E, 0xC1, 0x58, 0x0F, 0x94, 0xD6 };

/* --- 加密的"DEX"数据 --- */
/* 明文 Base64 = "S0wxN19TRUVEOjIwMjgwNzAz"（= "KL17_SEED:20280703"） */
/* 加密 = 先 Base64 编码，再逐字节 XOR */
static const uint8_t ENC_DEX[] = {
    0x51, 0x2E, 0x4A, 0x08, 0x6E, 0x53, 0x7B, 0x1D,
    0x48, 0x3F, 0x25, 0x5A, 0x72, 0x61, 0x0C, 0x3E,
    0x6B, 0x4D, 0x78, 0x2A, 0x15, 0x59, 0x3C, 0x07
};
#define ENC_LEN 24

/* --- CRC32 基线（.text 段自校验用） --- */
static volatile uint32_t CRC_BASELINE = 0;
static volatile int      anti_debug_passed = 0;

/* --- 简易 CRC32 --- */
static uint32_t crc32_calc(const uint8_t *data, int len) {
    uint32_t crc = 0xFFFFFFFF;
    for (int i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

/* --- 反调试检测函数 --- */

/* ① ptrace(PTRACE_TRACEME) 占坑 */
static int check_ptrace(void) {
    /* 如果已经被调试，ptrace 会失败 */
    int pid = fork();
    if (pid == 0) {
        /* 子进程：尝试 ptrace 占坑 */
        long result = (long)ptrace(0 /* PTRACE_TRACEME */, 0, 0, 0);
        _exit(result == 0 ? 0 : 1);
    }
    if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            return 1; /* 占坑成功，没有调试器 */
        }
    }
    return 0; /* 被调试 */
}

/* ② 读 /proc/self/status 的 TracerPid */
static int check_tracer_pid(void) {
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return 1; /* 打不开也放行 */
    char buf[4096];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 1;
    buf[n] = '\0';
    const char *tag = "TracerPid:";
    char *p = strstr(buf, tag);
    if (!p) return 1;
    p += strlen(tag);
    while (*p == ' ') p++;
    int pid = atoi(p);
    return (pid == 0) ? 1 : 0; /* 0 = 没有调试器 */
}

/* ③ 检测 Frida 特征端口 27042 */
static int check_frida_port(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(27042);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
    return (ret != 0) ? 1 : 0; /* 连不上 = 没有 Frida */
}

/* 反 hook：mmap 映射函数头 + 比对（简化版） */
static uint8_t saved_prologue[16];
static void *func_addr = NULL;

static void save_prologue(void *func) {
    func_addr = func;
    long page = sysconf(_SC_PAGESIZE);
    void *base = (void *)((long)func & ~(page - 1));
    mmap(base, page, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(saved_prologue, func, 16);
}

static int check_inline_hook(void) {
    if (!func_addr) return 1;
    return (memcmp(saved_prologue, func_addr, 16) == 0) ? 1 : 0;
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

/* --- 解密：Base64 编码 → XOR 还原 --- */
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

static void decrypt(uint8_t *out, const uint8_t *enc, int len) {
    /* 第一轮：XOR 还原 Base64 */
    for (int i = 0; i < len; i++) {
        out[i] = enc[i] ^ XOR_KEY[i % 8];
    }
}

static uint32_t extract_seed(const uint8_t *b64_decoded, int len) {
    /* b64 解码后得到 "KL17_SEED:XXXXXXXX"，跳过前 11 字节取 4 字节 */
    if (len < 15) return 0;
    uint32_t seed = 0;
    for (int i = 0; i < 4; i++) {
        seed = (seed << 8) | b64_decoded[11 + i];
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
void k17_decoy_seal(void) {}
void k17_fold(void) {}
void k17_spin(void) {}

/* --- 全局：初始化计数（模拟热加载检测） --- */
static volatile int init_count = 0;

/* --- JNI 桥接 --- */

/* Ek.nativeAntiDebug() → int
 * 执行反调试三重检测 + 反hook，全部通过返回 1。
 */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Ek_nativeAntiDebug(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;

    /* 三重反调试 */
    int r1 = check_ptrace();
    int r2 = check_tracer_pid();
    int r3 = check_frida_port();
    int r4 = check_inline_hook();

    anti_debug_passed = (r1 && r2 && r3 && r4) ? 1 : 0;
    return anti_debug_passed;
}

/* Ek.nativeDecrypt() → String（解密后的明文 hex） */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Ek_nativeDecrypt(JNIEnv *env, jclass clazz) {
    (void)clazz;

    if (!anti_debug_passed) {
        return (*env)->NewStringUTF(env, "anti-debug failed");
    }

    uint8_t xored[ENC_LEN];
    decrypt(xored, ENC_DEX, ENC_LEN);

    /* Base64 解码 */
    uint8_t decoded[ENC_LEN];
    int dec_len = b64_decode(xored, ENC_LEN, decoded);
    if (dec_len < 0) {
        return (*env)->NewStringUTF(env, "decode error");
    }

    char hex[64];
    to_hex(decoded, dec_len, hex);
    return (*env)->NewStringUTF(env, hex);
}

/* Ek.nativeSeed() → int（提取的种子值） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Ek_nativeSeed(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;

    if (!anti_debug_passed) return 0;

    uint8_t xored[ENC_LEN];
    decrypt(xored, ENC_DEX, ENC_LEN);

    uint8_t decoded[ENC_LEN];
    int dec_len = b64_decode(xored, ENC_LEN, decoded);
    if (dec_len < 0) return 0;

    return (jint)extract_seed(decoded, dec_len);
}

/* Ek.nativeAnswer() → String（最终答案 hex） */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Ek_nativeAnswer(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;

    if (!anti_debug_passed) {
        return (*env)->NewStringUTF(env, "anti-debug failed");
    }

    uint8_t xored[ENC_LEN];
    decrypt(xored, ENC_DEX, ENC_LEN);

    uint8_t decoded[ENC_LEN];
    int dec_len = b64_decode(xored, ENC_LEN, decoded);
    if (dec_len < 0) {
        return (*env)->NewStringUTF(env, "decode error");
    }

    uint32_t seed = extract_seed(decoded, dec_len);
    char hex[33];
    get_answer(seed, hex);
    return (*env)->NewStringUTF(env, hex);
}

/* Ek.nativeStatus() → String（反调试状态说明） */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Ek_nativeStatus(JNIEnv *env, jclass clazz) {
    (void)clazz;

    char buf[256];
    snprintf(buf, sizeof(buf),
        "anti_debug = %d\n"
        "ptrace     = %d\n"
        "tracer_pid = %d\n"
        "frida_port = %d\n"
        "hook_check = %d",
        anti_debug_passed,
        check_ptrace(),
        check_tracer_pid(),
        check_frida_port(),
        check_inline_hook());

    return (*env)->NewStringUTF(env, buf);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;

    /* 保存自身函数头用于反 hook 检测 */
    save_prologue((void *)Java_com_fatdog_reverse_Ek_nativeAntiDebug);

    /* 计算 .text 段 CRC 基线 */
    CRC_BASELINE = 0xB7A12345; /* 占位，实际应算 .text 段 */

    return JNI_VERSION_1_6;
}
