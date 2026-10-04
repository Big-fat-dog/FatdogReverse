/**
 * fuso_device_probe.c — 扶桑树 fuso_probe.h 真机验证驱动（2026-10-04）
 *
 * 为什么需要它：`fuso_probe.h` 里有「内存 vs 磁盘代码比对」这类会去**读别的
 * 模块代码段**的逻辑。宿主（Windows/mingw）没有 /proc，这些函数会整路跳过，
 * 于是「宿主全绿」并不能证明真机不崩——2026-10-04 KL26/KL27 就是这么翻车的：
 * Android 10 把 libc 的 .text 映射成 --xp（只执行不可读），直接解引用 SIGSEGV，
 * 打开关卡即闪退。
 *
 * 本程序把 fuso_probe.h 的每一路信号在本机跑一遍，并额外做一次**字节级对拍**
 * （libc 关键函数入口：/proc/self/mem 读到的内存 vs 磁盘 ELF），用来区分
 * 「真的读到了并比对」和「被守卫跳过所以返回 0」。
 *
 * 编译运行：见 tools/verify_fuso_device.py（自动交叉编译 + push + 运行）。
 */
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include "fuso_probe.h"

static void hexdump(const char *tag, const unsigned char *p, int n) {
    printf("%s", tag);
    for (int i = 0; i < n; i++) printf(" %02x", p[i]);
    printf("\n");
}

/* ==================================================================
 * ① 信号试点自检 —— 与 snow.cpp 的 FrostProbe（RAII 版）逻辑等价的 C 版
 *    目的：KL28 的 ① 路在宿主因无 Android 信号语义而被 #if 屏蔽（永不编译），
 *    存在「看着实现了、其实真机没跑过」的风险，故在真机驱动里等价复刻一份，
 *    用真机结果证明该路逻辑成立且干净环境返回 0。
 *    判定：SIGUSR1 未被他人预装 handler，且自装自触发能收到 → 返回 0（安全）。
 * ================================================================== */
#if defined(__ANDROID__)
static volatile sig_atomic_t g_u1_hits = 0;
static void on_u1(int s) { (void)s; g_u1_hits++; }

static int signal_trial(void) {
    struct sigaction cur, old, sa;
    memset(&cur, 0, sizeof(cur));
    if (sigaction(SIGUSR1, NULL, &cur) != 0) return 0;          /* 查不到 → 不记分 */
    if (cur.sa_handler != SIG_DFL && cur.sa_handler != SIG_IGN) return 1;  /* 已被劫持 */

    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    if (sigprocmask(SIG_UNBLOCK, &mask, &oldmask) != 0) return 0;
    if (sigaction(SIGUSR1, NULL, &old) != 0) { sigprocmask(SIG_SETMASK, &oldmask, NULL); return 0; }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_u1;
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        sigaction(SIGUSR1, &old, NULL);
        sigprocmask(SIG_SETMASK, &oldmask, NULL);
        return 0;
    }

    int fired = 0;
    g_u1_hits = 0;
    if (kill(getpid(), SIGUSR1) == 0) {
        struct timespec ts = {0, 200000};   /* 0.2ms */
        for (int i = 0; i < 50 && g_u1_hits == 0; i++) nanosleep(&ts, NULL);
        fired = (g_u1_hits != 0);
    }
    sigaction(SIGUSR1, &old, NULL);
    sigprocmask(SIG_SETMASK, &oldmask, NULL);
    return fired ? 0 : 1;
}
#endif

/* ② TracerPid 追踪 —— 等价 KL28 ChillProbe（只有真机有 /proc/self/status） */
static int tracerpid_probe(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    int tp = 0, seen = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) { tp = atoi(line + 10); seen = 1; break; }
    }
    fclose(f);
    return (seen && tp != 0) ? 1 : 0;
}

int main(void) {
    printf("=== fuso_probe device verification ===\n");

    struct fuso_lib lib;
    if (!fuso_find_libc(&lib)) {
        printf("libc        : NOT FOUND（6/7 会整路跳过，无法对拍）\n");
    } else {
        printf("libc        : %s\n", lib.path);
        printf("libc base   : %llx\n", (unsigned long long)lib.base);
    }
    fflush(stdout);

    /* ---------- 第一部分：字节级对拍，证明「真的读到了」 ---------- */
    int match = 0, mismatch = 0, skip = 0;
    if (lib.found) {
        int fd = open(lib.path, O_RDONLY);
        unsigned char eh[64];
        int is64 = 0;
        if (fd >= 0 && fuso_read_ehdr(fd, eh, &is64)) {
            printf("\n-- libc 代码段：内存(/proc/self/mem) vs 磁盘(ELF) --\n");
            const char *FUNCS[] = { "open", "openat", "read", "connect", "clock_gettime", NULL };
            for (int i = 0; FUNCS[i]; i++) {
                void *sym = dlsym(RTLD_DEFAULT, FUNCS[i]);
                if (!sym) continue;
                Dl_info di;
                if (!dladdr(sym, &di) || !di.dli_fname || !strstr(di.dli_fname, "libc.so")) continue;

                uint64_t rel = (uint64_t)(uintptr_t)sym - (uint64_t)(uintptr_t)di.dli_fbase;
                unsigned char disk[16], mem[16];
                int gd = fuso_read_disk_rel(fd, eh, is64, rel, disk, sizeof(disk));
                int gm = fuso_read_code(sym, mem, sizeof(mem));
                printf("%-14s rel=%#-10llx disk_ok=%d mem_ok=%d\n", FUNCS[i],
                       (unsigned long long)rel, gd, gm);
                if (!gd || !gm) { skip++; continue; }
                hexdump("   disk:", disk, 16);
                hexdump("   mem :", mem, 16);
                if (memcmp(disk, mem, 16) == 0) { match++;   printf("   => MATCH\n"); }
                else                            { mismatch++; printf("   => MISMATCH\n"); }
            }
        }
        if (fd >= 0) close(fd);
    }
    printf("\nbyte-compare summary: match=%d mismatch=%d skip=%d\n", match, mismatch, skip);
    fflush(stdout);

    /* ---------- 第二部分：各路信号（干净环境应全 0） ---------- */
    printf("\n-- 检测信号（干净环境期望 0）--\n");
#if defined(__ANDROID__)
    printf("1 signal_trial  : %d\n", signal_trial());       fflush(stdout);
#endif
    printf("2 tracerpid     : %d\n", tracerpid_probe());    fflush(stdout);
    printf("3 smaps_dirty   : %d\n", fuso_smaps_dirty());   fflush(stdout);
    printf("4 anon_exec     : %d\n", fuso_anon_exec());     fflush(stdout);
    printf("5 trampoline    : %d\n", fuso_trampoline());    fflush(stdout);
    printf("6 libc_prologue : %d\n", fuso_libc_prologue()); fflush(stdout);
    printf("7 libc_scan     : %d\n", fuso_libc_scan());     fflush(stdout);
    printf("8 libc_got      : %d\n", fuso_libc_got());      fflush(stdout);

    /* 重复调用，确认无状态副作用、不崩 */
    printf("6 libc_prologue : %d (2nd)\n", fuso_libc_prologue()); fflush(stdout);
    printf("7 libc_scan     : %d (2nd)\n", fuso_libc_scan());     fflush(stdout);

    printf("\nDONE (no crash)\n");
    return 0;
}
