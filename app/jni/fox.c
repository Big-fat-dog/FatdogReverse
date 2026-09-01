/*
 * 扶桑树 KL21：枯叶听风——端口探测 + D-Bus 协议指纹检测。
 *
 * 两路 Frida 检测：
 *   ① 端口探测：connect() 27042/27043/27044（Frida 默认监听端口）
 *   ② D-Bus 指纹：读 /proc/net/tcp 找 local_address 匹配 D-Bus 连接特征
 *      （Frida 通过 D-Bus 与目标进程通信，消息头魔数 l\0\0\1 = 0x6C000001）
 * 两路 OR 判定——任一检出即判定 Frida 存在。
 *
 * 标记（真）：Fatdog_breeze — UTF-16 码元。
 * 诱饵（假）：Fatdog_gust   — 一字之差。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* --- 真标记：Fatdog_breeze（UTF-16LE） --- */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0062, 0x0072, 0x0065, 0x0065, 0x007A, 0x0065
};
#define MARKER_LEN 13

/* --- 诱饵：Fatdog_gust --- */
static const jchar DECOY[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0067, 0x0075, 0x0073, 0x0074
};
#define DECOY_LEN 11

/* --- 常量 --- */
#define SEED 20280715

/* Frida 默认端口 */
static const int FRIDA_PORTS[] = {27042, 27043, 27044};
#define NUM_PORTS 3

/* D-Bus 消息头魔数（l\0\0\1 = 0x6C000001，大端） */
#define DBUS_MAGIC 0x6C000001

/* ============================================================
 * SHA-256（复刻项目内标准实现）
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
 * 检测①：端口探测（connect 27042/27043/27044）
 * ============================================================ */
static int detect_port_scan(void) {
    for (int i = 0; i < NUM_PORTS; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(FRIDA_PORTS[i]);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        /* 非阻塞 + 短超时 */
        struct timeval tv = {0, 300000}; /* 300ms */
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        int r = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
        close(fd);
        if (r == 0) return 1; /* 端口开放 → Frida 可能存在 */
    }
    return 0;
}

/* ============================================================
 * 检测②：D-Bus 协议指纹（解析 /proc/net/tcp）
 * ============================================================ */
static int detect_dbus_fingerprint(void) {
    int fd = open("/proc/net/tcp", O_RDONLY);
    if (fd < 0) return 0;
    char buf[4096];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';

    /* 跳过首行标题 */
    char *line = strchr(buf, '\n');
    if (!line) return 0;
    line++;

    while (*line && *line != '\0') {
        /* 格式：sl local_address rem_address st ... */
        /* 跳过前导空格 */
        while (*line == ' ' || *line == '\t') line++;
        if (*line == '\0' || *line == '\n') { line++; continue; }

        /* 跳过 sl 列 */
        char *p = strchr(line, ' ');
        if (!p) break;
        while (*p == ' ') p++;

        /* local_address: hex8:hex4 */
        char *colon = strchr(p, ':');
        if (!colon) break;
        /* 取 32-bit local_address（高 32 位，IPv4） */
        char addr_str[16];
        int len = (int)(colon - p);
        if (len >= (int)sizeof(addr_str)) { line = strchr(p, '\n'); if (line) line++; continue; }
        memcpy(addr_str, p, len);
        addr_str[len] = '\0';
        uint32_t local_addr = (uint32_t)strtoul(addr_str, NULL, 16);

        /* D-Bus 默认监听 0.0.0.0:1234 → local_address = 00000000:04D2
         * 但 Frida 注入后 D-Bus socket 绑定的地址需要匹配特征。
         * 我们检查 local_address 的 port 部分是否是常见 D-Bus 端口
         * 或者 address 是否包含 0.0.00000001（loopback D-Bus） */
        char *sp = colon + 1;
        while (*sp == ' ') sp++;
        char port_str[16];
        char *sp2 = strchr(sp, ' ');
        if (!sp2) break;
        int plen = (int)(sp2 - sp);
        if (plen >= (int)sizeof(port_str)) { line = strchr(p, '\n'); if (line) line++; continue; }
        memcpy(port_str, sp, plen);
        port_str[plen] = '\0';
        uint32_t local_port = (uint32_t)strtoul(port_str, NULL, 16);

        /* D-Bus 系统总线默认端口 1234 (0x04D2) 或 session bus 通常是随机高端口
         * Frida 的 D-Bus 通道会绑定到 loopback 的高端口，关键是看
         * local_address 是否为 0100007F（127.0.0.1 大端） */
        if (local_addr == 0x0100007F && local_port > 1024) {
            /* 进一步检查：对端端口必须是 frida-server 的默认监听端口。
             * 注入后的 agent 会建立 127.0.0.1:27042-27044 连接；
             * 只匹配本地 loopback 高端口会误报（正常 App 也常有 loopback 连接）。 */
            char *rem_start = sp2 + 1;
            while (*rem_start == ' ') rem_start++;
            char *rem_end = strchr(rem_start, ' ');
            if (!rem_end) break;
            char *rem_colon = strchr(rem_start, ':');
            if (!rem_colon || rem_colon >= rem_end) break;
            int rem_plen = (int)(rem_end - rem_colon - 1);
            if (rem_plen >= (int)sizeof(port_str)) { line = strchr(p, '\n'); if (line) line++; continue; }
            char rem_port_str[16];
            memcpy(rem_port_str, rem_colon + 1, rem_plen);
            rem_port_str[rem_plen] = '\0';
            uint32_t remote_port = (uint32_t)strtoul(rem_port_str, NULL, 16);
            if (remote_port != 27042 && remote_port != 27043 && remote_port != 27044) {
                line = strchr(p, '\n'); if (line) line++; continue;
            }

            /* 状态 01 = ESTABLISHED */
            char *st_start = rem_end;
            while (*st_start == ' ') st_start++;
            char *st_end = strchr(st_start, ' ');
            if (!st_end) break;
            char st_str[8];
            int st_len = (int)(st_end - st_start);
            if (st_len >= (int)sizeof(st_str)) { line = strchr(p, '\n'); if (line) line++; continue; }
            memcpy(st_str, st_start, st_len);
            st_str[st_len] = '\0';
            uint32_t state = (uint32_t)strtoul(st_str, NULL, 16);

            if (state == 1) { /* ESTABLISHED */
                return 1;
            }
        }

        line = strchr(p, '\n');
        if (line) line++;
        else break;
    }
    return 0;
}

/* ============================================================
 * 状态查询（给 Java 层读取详细信息）
 * ============================================================ */
static volatile int g_port_result = 0;
static volatile int g_dbus_result = 0;

/* --- 诱饵导出 --- */
void k21_decoy_breeze(void) {}
void k21_gust_decoy(void) {}

/* ============================================================
 * JNI 桥接
 * ============================================================ */

/* Lk.nativeFridaDetect() → int（0=安全 1=检出） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Lk_nativeFridaDetect(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    g_port_result = detect_port_scan();
    g_dbus_result = detect_dbus_fingerprint();
    return (g_port_result || g_dbus_result) ? 1 : 0;
}

/* Lk.nativePortScan() → int（端口探测子结果） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Lk_nativePortScan(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return g_port_result;
}

/* Lk.nativeDbusFingerprint() → int（D-Bus 指纹子结果） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Lk_nativeDbusFingerprint(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return g_dbus_result;
}

/* Lk.nativeAnswer() → String（最终答案，不受检测结果影响） */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Lk_nativeAnswer(JNIEnv *env, jclass clazz) {
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

/* Lk.nativeStatus() → String（检测详情） */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Lk_nativeStatus(JNIEnv *env, jclass clazz) {
    (void)clazz;
    char buf[256];
    snprintf(buf, sizeof(buf),
        "port_scan = %d (27042-27044)\n"
        "dbus_fp   = %d (/proc/net/tcp)\n"
        "combined  = %d",
        g_port_result, g_dbus_result,
        (g_port_result || g_dbus_result) ? 1 : 0);
    return (*env)->NewStringUTF(env, buf);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    return JNI_VERSION_1_6;
}
