/*
 * 扶桑树 KL23：照妖显形——运行时 ELF 三路校验（AND 判定）。
 *
 * 与 KL21/22 的 OR 判定不同：本关要求三路条件同时成立才判定检出。
 *
 *   ① maps hex pattern：流式解析 /proc/self/maps，搜索 r-xp 段中的 frida 特征字节
 *   ② 运行时 DT_DEBUG：通过 dl_iterate_phdr 读取主程序链接器写入的运行时值
 *   ③ auxv 结构自洽：getauxval + AT_PHDR 程序头表校验（纯内存，不碰 /proc）
 *
 * 注意：只启动 frida-server 时本关必然全 0 —— server 是独立进程，
 * 目标 app 的 maps 里没有它；必须真正 attach 注入后 r-xp 段才会出现
 * /memfd:frida-agent-*.so。本关检的是「注入后的运行时痕迹」。
 *
 * 标记（真）：Fatdog_gleam — UTF-16 码元。
 * 诱饵（假）：Fatdog_glint — 一字之差。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <link.h>
#include <sys/auxv.h>

/* --- 真标记：Fatdog_gleam（UTF-16LE） --- */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0067, 0x006C, 0x0065, 0x0061, 0x006D
};
#define MARKER_LEN 12

/* --- 诱饵：Fatdog_glint --- */
static const jchar DECOY[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0067, 0x006C, 0x0069, 0x006E, 0x0074
};
#define DECOY_LEN 12

/* --- 常量 --- */
#define SEED 20280717

/* Frida 特征字节序列（简化版） */
static const uint8_t FRIDA_SIG[] = { 0x66, 0x72, 0x69, 0x64, 0x61 }; /* "frida" */
#define SIG_LEN 5

/* ============================================================
 * SHA-256
 * ============================================================ */
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
#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)(((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z)(((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x)(RR(x,2)^RR(x,13)^RR(x,22))
#define EP1(x)(RR(x,6)^RR(x,11)^RR(x,25))
#define SIG0(x)(RR(x,7)^RR(x,18)^((x)>>3))
#define SIG1(x)(RR(x,17)^RR(x,19)^((x)>>10))

static void sha256(const uint8_t *msg, size_t len, uint8_t out[32]) {
    uint32_t h[]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
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
            uint32_t t1=hh+EP1(e)+CH(e,f,g)+K256[i]+w[i],t2=EP0(a)+MAJ(a,b,c);
            hh=g;g=f;f=e;d+=t1;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    for(int i=0;i<8;i++){out[i*4]=(uint8_t)(h[i]>>24);out[i*4+1]=(uint8_t)(h[i]>>16);out[i*4+2]=(uint8_t)(h[i]>>8);out[i*4+3]=(uint8_t)h[i];}
}

static void to_hex(const uint8_t *in, int n, char *out) {
    const char *t = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[i*2] = t[(in[i]>>4)&0xF]; out[i*2+1] = t[in[i]&0xF]; }
    out[n*2] = '\0';
}

/* ============================================================
 * 检测①：maps hex pattern（在 r-xp 段搜索 frida 特征字节）
 *
 * 流式行缓冲：旧实现用固定 16KB 整块缓冲，首次 read 填到 16383 字节后
 * total 已满，第二次 read 请求 0 字节直接 break —— 真机 /proc/self/maps
 * 约 260KB，覆盖率只有 6%，而注入的 agent 永远映射在表尾，等于恒不命中。
 * 现改为 8KB 分块 read + 行缓冲续接，无总长上限。
 * ============================================================ */
#define MAPS_LINE_MAX 512

static int line_is_rx_hit(const char *line, int len) {
    /* maps 行：start-end perms offset dev inode pathname
     * 权限字段从第一个空格之后开始，要求 r-xp（可执行映射）。 */
    int i = 0;
    while (i < len && line[i] != ' ') i++;
    if (i + 4 >= len) return 0;

    const char *perm = line + i + 1;
    if (perm[0] != 'r' || perm[2] != 'x' || perm[3] != 'p') return 0;

    for (int k = 0; k + SIG_LEN <= len; k++) {
        if (memcmp(line + k, FRIDA_SIG, SIG_LEN) == 0) return 1;
    }
    return 0;
}

static int detect_maps_hex(void) {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return 0;

    char chunk[8192];
    char line[MAPS_LINE_MAX];
    int line_len = 0;
    int overflow = 0;   /* 超长行：截断丢弃，但不打断后续行 */
    int found = 0;

    for (;;) {
        ssize_t n = read(fd, chunk, sizeof(chunk));
        if (n <= 0) break;

        for (ssize_t i = 0; i < n; i++) {
            char c = chunk[i];
            if (c == '\n') {
                if (!overflow && line_is_rx_hit(line, line_len)) found = 1;
                line_len = 0;
                overflow = 0;
                if (found) break;
                continue;
            }
            if (line_len < MAPS_LINE_MAX - 1) line[line_len++] = c;
            else overflow = 1;
        }
        if (found) break;
    }

    /* 末尾没有换行的残行也要检查 */
    if (!found && line_len > 0 && !overflow) {
        if (line_is_rx_hit(line, line_len)) found = 1;
    }

    close(fd);
    return found;
}

/* ============================================================
 * 检测②：运行时 DT_DEBUG 校验
 *
 * 磁盘 ELF 中的 DT_DEBUG 固定为 0，不能直接拿来判断。
 * 这里用 AT_PHDR 定位主程序，再通过 dl_iterate_phdr 读取链接器
 * 已写入运行时内存的 PT_DYNAMIC，确认 DT_DEBUG 已初始化。
 * ============================================================ */
typedef struct {
    uintptr_t phdr_addr;
    int found;
} dt_debug_ctx_t;

static int inspect_runtime_dt_debug(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    dt_debug_ctx_t *ctx = (dt_debug_ctx_t *)data;
    if (ctx->found || info == NULL || info->dlpi_phdr == NULL) return 0;

    uintptr_t phdr_start = (uintptr_t)info->dlpi_phdr;
    uintptr_t phdr_end = phdr_start + (uintptr_t)info->dlpi_phnum * sizeof(ElfW(Phdr));
    if (ctx->phdr_addr < phdr_start || ctx->phdr_addr >= phdr_end) return 0;

    for (unsigned i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_DYNAMIC) continue;

        ElfW(Dyn) *dyn = (ElfW(Dyn) *)((uintptr_t)info->dlpi_addr + (uintptr_t)ph->p_vaddr);
        size_t count = (size_t)(ph->p_memsz / sizeof(ElfW(Dyn)));
        for (size_t j = 0; j < count; j++) {
            if (dyn[j].d_tag == DT_NULL) break;
            if (dyn[j].d_tag == DT_DEBUG && dyn[j].d_un.d_ptr != 0) {
                ctx->found = 1;
                break;
            }
        }
        break;
    }
    return 0;
}

static int detect_dt_debug(void) {
    uintptr_t at_phdr = (uintptr_t)getauxval(AT_PHDR);
    if (at_phdr == 0) return 0;

    dt_debug_ctx_t ctx = { at_phdr, 0 };
    dl_iterate_phdr(inspect_runtime_dt_debug, &ctx);
    return ctx.found;
}

/* ============================================================
 * 校验③：auxv 一致性（纯内存校验，不读 /proc）
 *
 * 旧实现要读 /proc/self/exe（zygote_exec 标签，untrusted_app 读被
 * SELinux 拦）与 /proc/self/auxv，任一失败立即 return 0。真机上这一路
 * 恒为 0，三路 AND 因此永远不成立 —— 本关永远抓不到注入。
 *
 * 现改为只用 getauxval + AT_PHDR 指向的程序头表做自洽校验：
 *   • AT_PHENT 必须等于当前 ABI 的 ElfW(Phdr) 大小
 *   • 表内必须有 PT_PHDR，且 p_filesz == phnum * phent
 *     （PT_PHDR 描述的就是程序头表本身，大小不符说明表被替换/伪造）
 *   • load_bias = AT_PHDR - PT_PHDR.p_vaddr 必须页对齐
 *   • 首个 PT_LOAD 的 p_offset 与 p_vaddr 页内偏移必须一致（mmap 硬约束）
 * 全部成立才返回 1，作为 AND 判定中的运行时结构守卫。
 * ============================================================ */
static int detect_auxv(void) {
    uintptr_t phdr_addr = (uintptr_t)getauxval(AT_PHDR);
    size_t phent = (size_t)getauxval(AT_PHENT);
    size_t phnum = (size_t)getauxval(AT_PHNUM);
    if (phdr_addr == 0 || phnum == 0 || phnum > 512) return 0;
    if (phent != sizeof(ElfW(Phdr))) return 0;

    const ElfW(Phdr) *ph = (const ElfW(Phdr) *)phdr_addr;
    uintptr_t load_bias = 0;
    int has_phdr = 0;

    for (size_t i = 0; i < phnum; i++) {
        if (ph[i].p_type != PT_PHDR) continue;
        if ((uintptr_t)ph[i].p_vaddr > phdr_addr) return 0;
        if ((size_t)ph[i].p_filesz != phnum * phent) return 0;
        load_bias = phdr_addr - (uintptr_t)ph[i].p_vaddr;
        has_phdr = 1;
        break;
    }
    if (!has_phdr) return 0;
    if ((load_bias & 0xFFFULL) != 0) return 0;

    for (size_t i = 0; i < phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        if ((ph[i].p_offset & 0xFFFULL) != ((uintptr_t)ph[i].p_vaddr & 0xFFFULL)) return 0;
        break;
    }
    return 1;
}

/* 综合检测（供 nativeFridaDetect 与 nativeAnswer 共用） */
static int detect_frida_present(void) {
    return detect_maps_hex() && detect_dt_debug() && detect_auxv();
}

/* ============================================================
 * 状态
 * ============================================================ */
static volatile int g_hex_result = 0;
static volatile int g_dt_result = 0;
static volatile int g_auxv_result = 0;

/* --- 诱饵导出 --- */
void k23_decoy_gleam(void) {}
void k23_glint_decoy(void) {}

/* ============================================================
 * JNI 桥接
 * ============================================================ */

/* Ok.nativeFridaDetect() → int（三路 AND） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Ok_nativeFridaDetect(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    g_hex_result = detect_maps_hex();
    g_dt_result = detect_dt_debug();
    g_auxv_result = detect_auxv();
    /* 三路 AND：maps 命中且两路运行时结构校验成立才判定检出 */
    return detect_frida_present();
}

/* Ok.nativeMapsHex() → int */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Ok_nativeMapsHex(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return g_hex_result;
}

/* Ok.nativeDtDebug() → int */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Ok_nativeDtDebug(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return g_dt_result;
}

/* Ok.nativeAuxv() → int */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Ok_nativeAuxv(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return g_auxv_result;
}

/* Ok.nativeAnswer() → String */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Ok_nativeAnswer(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    if (detect_frida_present()) {
        return (*env)->NewStringUTF(env, "DETECTED_FRIDA_LOCKED_ANSWER");
    }
    uint8_t buf[4] = {
        (uint8_t)(SEED >> 24), (uint8_t)(SEED >> 16),
        (uint8_t)(SEED >> 8),  (uint8_t)SEED
    };
    uint8_t h[32];
    sha256(buf, 4, h);
    char hex[65];
    to_hex(h, 32, hex);
    return (*env)->NewStringUTF(env, hex);
}

/* Ok.nativeStatus() → String */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Ok_nativeStatus(JNIEnv *env, jclass clazz) {
    (void)clazz;
    char buf[256];
    snprintf(buf, sizeof(buf),
        "maps_hex = %d (frida bytes in r-xp)\n"
        "dt_debug = %d (runtime DT_DEBUG)\n"
        "auxv     = %d (phdr self-consistent)\n"
        "combined = %d (3-way AND)",
        g_hex_result, g_dt_result, g_auxv_result,
        (g_hex_result && g_dt_result && g_auxv_result) ? 1 : 0);
    return (*env)->NewStringUTF(env, buf);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    return JNI_VERSION_1_6;
}
