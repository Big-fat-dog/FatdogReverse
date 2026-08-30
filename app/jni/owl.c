/*
 * 扶桑树 KL22：落影寻痕——/proc/self/fd 扫描 + maps 搜索。
 *
 * 两路 Frida 检测：
 *   ① fd 扫描：遍历 /proc/self/fd，readlink 检查 memfd:frida-agent
 *   ② maps 搜索：解析 /proc/self/maps 搜索 "frida" 相关路径字符串
 * 两路 OR 判定——任一检出即判定 Frida 存在。
 *
 * 标记（真）：Fatdog_shadow — UTF-16 码元。
 * 诱饵（假）：Fatdog_shade  — 一字之差。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>

/* --- 真标记：Fatdog_shadow（UTF-16LE） --- */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0073, 0x0068, 0x0061, 0x0064, 0x006F, 0x0077
};
#define MARKER_LEN 13

/* --- 诱饵：Fatdog_shade --- */
static const jchar DECOY[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0073, 0x0068, 0x0061, 0x0064, 0x0065
};
#define DECOY_LEN 12

/* --- 常量 --- */
#define SEED 20280716

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
 * 检测①：/proc/self/fd 扫描（memfd:frida-agent）
 * ============================================================ */
static int detect_fd_scan(void) {
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) return 0;

    char link[256];
    struct dirent *ent;
    int found = 0;

    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        /* readlink /proc/self/fd/{fd} → 检查是否含 frida */
        char path[64];
        snprintf(path, sizeof(path), "/proc/self/fd/%s", ent->d_name);

        ssize_t len = readlink(path, link, sizeof(link) - 1);
        if (len <= 0) continue;
        link[len] = '\0';

        /* 检查 memfd:frida-agent */
        if (strstr(link, "memfd:frida") != NULL) {
            found = 1;
            break;
        }

        /* 也检查 /proc/self/fdinfo/{fd} 中的 memfd 标记 */
        char fdi_path[64];
        snprintf(fdi_path, sizeof(fdi_path), "/proc/self/fdinfo/%s", ent->d_name);
        int fdi_fd = open(fdi_path, O_RDONLY);
        if (fdi_fd >= 0) {
            char buf[512];
            int n = read(fdi_fd, buf, sizeof(buf) - 1);
            close(fdi_fd);
            if (n > 0) {
                buf[n] = '\0';
                if (strstr(buf, "memfd:frida") != NULL) {
                    found = 1;
                    break;
                }
            }
        }
    }
    closedir(dir);
    return found;
}

/* ============================================================
 * 检测②：/proc/self/maps 搜索 frida 字符串
 * ============================================================ */
static int detect_maps_scan(void) {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return 0;

    char buf[8192];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';

    /* 搜索 frida 相关关键词 */
    static const char *keywords[] = {
        "frida", "gadget", "gum-js-loop", "linjector",
        "re.frida.server", "frida-agent", NULL
    };

    for (int i = 0; keywords[i] != NULL; i++) {
        if (strstr(buf, keywords[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

/* ============================================================
 * 状态
 * ============================================================ */
static volatile int g_fd_result = 0;
static volatile int g_maps_result = 0;

/* --- 诱饵导出 --- */
void k22_decoy_shadow(void) {}
void k22_shade_decoy(void) {}

/* ============================================================
 * JNI 桥接
 * ============================================================ */

/* Nk.nativeFridaDetect() → int */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Nk_nativeFridaDetect(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    g_fd_result = detect_fd_scan();
    g_maps_result = detect_maps_scan();
    return (g_fd_result || g_maps_result) ? 1 : 0;
}

/* Nk.nativeFdScan() → int */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Nk_nativeFdScan(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return g_fd_result;
}

/* Nk.nativeMapsScan() → int */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Nk_nativeMapsScan(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return g_maps_result;
}

/* Nk.nativeAnswer() → String */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Nk_nativeAnswer(JNIEnv *env, jclass clazz) {
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

/* Nk.nativeStatus() → String */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Nk_nativeStatus(JNIEnv *env, jclass clazz) {
    (void)clazz;
    char buf[256];
    snprintf(buf, sizeof(buf),
        "fd_scan  = %d (memfd:frida-agent)\n"
        "maps_scan = %d (frida in /proc/self/maps)\n"
        "combined = %d",
        g_fd_result, g_maps_result,
        (g_fd_result || g_maps_result) ? 1 : 0);
    return (*env)->NewStringUTF(env, buf);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    return JNI_VERSION_1_6;
}
