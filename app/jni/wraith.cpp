/* 自动生成：python gen_kkl5.py —— 请勿手改。 */
/* 太玄之初 KKL5 诛仙台 · 五 so 编队（门面/虚拟机/复合分组/摘要/守卫）。 */

/*
 * wraith —— 太玄之初 KKL5 诛仙台的完整性守卫（评分阈值制）。
 *
 * 五路（全部只查"有没有人动过我的代码/运行环境"，**不内置任何第三方注入框架检测**，
 * 对齐太玄之初的守卫白名单 G1/G3/G4/G5，避免与扶桑树分区撞题）：
 *   ① 调试器痕迹  /proc/self/status:TracerPid
 *   ② 段权限审计  自身映射里出现可写+可执行的段
 *   ③ 断点痕迹    本函数首 4 字节是否为 BRK / INT3 编码
 *   ④ 环境检测    ro.kernel.qemu 等模拟器特征
 *   ⑤ 自映射完整性 自身 so 的可执行段被标记 `(deleted)`（文件被替换/删除后仍在内存执行）
 *
 * 返回命中位掩码；上层按"命中数 >= 2"判风险，命中即静默投毒（签名主钥翻位）。
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/system_properties.h>

#define WR_VIS __attribute__((visibility("default")))

#define HIT_TRACE   1
#define HIT_SECTION 2
#define HIT_BREAK   4
#define HIT_EMU     8
#define HIT_SELF    16

static int wr_tracer(void) {
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return 0;
    char buf[4096];
    int n = (int)read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    char *p = strstr(buf, "TracerPid:");
    if (!p) return 0;
    return atoi(p + 10) != 0 ? 1 : 0;
}

static int wr_section(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    int hit = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "rwx")) { hit = 1; break; }
    }
    fclose(f);
    return hit;
}

static int wr_break(void) {
    uint32_t head = 0;
    memcpy(&head, (const void *)(uintptr_t)&wr_break, 4);
    if (head == 0xD4200000u) return 1;                            /* BRK #0（AArch64） */
    if (head == 0xCCCCCCCCu || (head & 0xFF) == 0xCC) return 1;   /* INT3（x86 兼容） */
    return 0;
}

static int wr_selfmap(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    static const char *own[] = {
        "libspindle.so", "libvellum.so", "libnimbus.so",
        "libtallow.so", "libwraith.so", 0
    };
    char line[512];
    int hit = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, " r-x") && !strstr(line, "rwx")) continue;
        if (!strstr(line, " (deleted)")) continue;
        for (int i = 0; own[i]; i++) {
            if (strstr(line, own[i])) { hit = 1; break; }
        }
        if (hit) break;
    }
    fclose(f);
    return hit;
}

static int wr_emulator(void) {
    char v[128];
    if (__system_property_get("ro.kernel.qemu", v) > 0 && v[0] == '1') return 1;
    if (__system_property_get("init.svc.qemud", v) > 0 && strcmp(v, "running") == 0) return 1;
    if (__system_property_get("ro.build.characteristics", v) > 0 && strstr(v, "emulator")) return 1;
    return 0;
}

extern "C" WR_VIS int wr_scan(int *detail) {
    int bits = 0;
    if (wr_tracer())   bits |= HIT_TRACE;
    if (wr_section())  bits |= HIT_SECTION;
    if (wr_break())    bits |= HIT_BREAK;
    if (wr_emulator()) bits |= HIT_EMU;
    if (wr_selfmap())  bits |= HIT_SELF;
    if (detail) *detail = bits;
    return bits;
}
