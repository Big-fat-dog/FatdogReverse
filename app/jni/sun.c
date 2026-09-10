/*
 * 扶桑树 KL23：照妖显形——运行时 ELF 三路校验（AND 判定）。
 *
 * 与 KL21/22 的 OR 判定不同：本关要求三路条件同时成立才判定检出。
 *
 *   ① maps hex pattern：解析 /proc/self/maps，搜索 r-xp 段中的 frida 特征字节
 *   ② 运行时 DT_DEBUG：通过 dl_iterate_phdr 读取主程序链接器写入的运行时值
 *   ③ auxv 校验：读 /proc/self/auxv，按 ELF class 解析并与磁盘 ELF 头交叉校验
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
 * ============================================================ */
static int detect_maps_hex(void) {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return 0;

    char buf[16384];
    int total = 0;
    int found = 0;

    while (!found) {
        int n = read(fd, buf + total, sizeof(buf) - total - 1);
        if (n <= 0) break;
        total += n;
        buf[total] = '\0';

        /* 逐行扫描 */
        char *nl_last = NULL;
        char *line = buf;
        while (*line) {
            char *nl = strchr(line, '\n');
            int line_len = nl ? (int)(nl - line) : (int)strlen(line);

            /* 检查是否是 r-xp 段（可执行） */
            char *perm = memchr(line, ' ', line_len);
            if (perm && perm + 4 < line + line_len) {
                if (memcmp(perm, " r-xp", 5) == 0) {
                    /* 在整行（含路径）中搜索特征字节 */
                    for (int i = 0; i < line_len - SIG_LEN; i++) {
                        if (memcmp(line + i, FRIDA_SIG, SIG_LEN) == 0) {
                            found = 1;
                            break;
                        }
                    }
                }
            }
            if (found) break;
            nl_last = nl;
            line = nl ? nl + 1 : line + line_len;
        }
        if (nl_last == NULL) break;
        /* 保留最后一行不完整数据 */
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
 * 读取 /proc/self/exe 的 ELF 头信息（类 + phoff/phentsize/phnum）
 * ============================================================ */
static int read_elf_info(int *is_64, uint64_t *phoff,
                         uint16_t *phentsize, uint16_t *phnum) {
    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0) return 0;

    uint8_t h[64];
    ssize_t got = read(fd, h, 16);
    if (got != 16 || h[0] != 0x7f || h[1] != 'E' || h[2] != 'L' || h[3] != 'F') {
        close(fd);
        return 0;
    }
    int is64 = (h[4] == 2);
    lseek(fd, 0, SEEK_SET);
    got = read(fd, h, is64 ? 64 : 52);
    if (got != (is64 ? 64 : 52)) { close(fd); return 0; }

    if (is64) {
        *is_64 = 1;
        *phoff = (uint64_t)h[32] | ((uint64_t)h[33] << 8) |
                 ((uint64_t)h[34] << 16) | ((uint64_t)h[35] << 24) |
                 ((uint64_t)h[36] << 32) | ((uint64_t)h[37] << 40) |
                 ((uint64_t)h[38] << 48) | ((uint64_t)h[39] << 56);
        *phentsize = (uint16_t)(h[54] | (h[55] << 8));
        *phnum = (uint16_t)(h[56] | (h[57] << 8));
    } else {
        *is_64 = 0;
        *phoff = (uint64_t)(h[28] | (h[29] << 8) | (h[30] << 16) | (h[31] << 24));
        *phentsize = (uint16_t)(h[42] | (h[43] << 8));
        *phnum = (uint16_t)(h[44] | (h[45] << 8));
    }
    close(fd);
    return 1;
}

static uint64_t rd_le64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

static uint32_t rd_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ============================================================
 * 校验③：辅助向量一致性（读 /proc/self/auxv，与磁盘 ELF 头交叉比对）
 * 64 位设备上 auxv 条目是 16 字节（Elf64_auxv_t：type+value 各 8 字节），
 * 32 位是 8 字节。旧实现按 32 位解析会把 AT_PHDR 的值读到 type 的高 32 位
 * （恒为 0）造成 64 位设备误报，这里按 ELF class 取正确宽度。
 * 返回 1 表示元数据一致；该结果作为 AND 判定中的运行时环境守卫。
 * ============================================================ */
static int detect_auxv(void) {
    int is_64 = 0;
    uint64_t elf_phoff = 0;
    uint16_t elf_phentsize = 0, elf_phnum = 0;
    if (!read_elf_info(&is_64, &elf_phoff, &elf_phentsize, &elf_phnum)) return 0;

    int fd = open("/proc/self/auxv", O_RDONLY);
    if (fd < 0) return 0;

    uint8_t buf[1024];
    int n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n <= 0) return 0;

    size_t ent = is_64 ? 16 : 8;
    uint64_t at_phdr = 0, at_phent = 0, at_phnum = 0;
    int has_phdr = 0, has_phent = 0, has_phnum = 0;
    size_t i = 0;
    while (i + ent <= (size_t)n) {
        uint64_t a_type, a_val;
        if (is_64) {
            a_type = rd_le64(buf + i);
            a_val = rd_le64(buf + i + 8);
        } else {
            a_type = rd_le32(buf + i);
            a_val = rd_le32(buf + i + 4);
        }
        if (a_type == 0) break; /* AT_NULL */
        if (a_type == 3) { at_phdr = a_val; has_phdr = 1; }       /* AT_PHDR */
        else if (a_type == 4) { at_phent = a_val; has_phent = 1; } /* AT_PHENT */
        else if (a_type == 5) { at_phnum = a_val; has_phnum = 1; } /* AT_PHNUM */
        i += ent;
    }

    /* AT_PHDR 低 12 位应等于 e_phoff 低 12 位（load_bias 页对齐），
     * PHENT/PHNUM 必须与磁盘 ELF 头一致。 */
    if (!has_phdr || !has_phent || !has_phnum) return 0;
    if (at_phdr == 0) return 0;
    if (at_phent != elf_phentsize) return 0;
    if (at_phnum != elf_phnum) return 0;
    if ((at_phdr & 0xFFFULL) != (elf_phoff & 0xFFFULL)) return 0;
    return 1;
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
    return (g_hex_result && g_dt_result && g_auxv_result) ? 1 : 0;
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
        "auxv     = %d (auxv/ELF consistent)\n"
        "combined = %d (3-way AND)",
        g_hex_result, g_dt_result, g_auxv_result,
        (g_hex_result && g_dt_result && g_auxv_result) ? 1 : 0);
    return (*env)->NewStringUTF(env, buf);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    return JNI_VERSION_1_6;
}
