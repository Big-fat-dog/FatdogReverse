/**
 * fuso_probe.h — 扶桑树「注入痕迹」检测信号库（header-only，2026-10-04）
 *
 * 背景：KL21-25 的检测全部走 libc 明文接口（fopen/read/opendir/connect），
 *       遇到 strongR-frida / Florida（特征串随机化）或 hook libc 喂假内容时失效。
 *       看雪 Sentry 系列点名的三块硬货——「可执行段私有脏页 / 匿名可执行代码岛 +
 *       跳板扫描 / libc 磁盘对内存完整性」——本项目此前一块都没有。
 *
 * 本头把这几路收敛成一组 static inline 函数，供 KL26/27/28 三关按需引用
 * （未引用的函数不会产生 -Wunused-function，因为都是 static inline）。
 *
 *   ③ fuso_smaps_dirty()   可执行(file-backed)段私有脏页 Private_Dirty 异常
 *   ④ fuso_anon_exec()     无名可执行映射——可疑「代码岛」
 *   ⑤ fuso_trampoline()    代码岛内 ARM64 跳板(LDR X16/17,[PC] / BR X16/17)扫描
 *   ⑥ fuso_libc_prologue() libc 关键函数入口 内存 vs 磁盘比对（抓 inline hook）
 *   ⑦ fuso_libc_scan()     libc 代码段多点采样 内存 vs 磁盘比对（抓非入口补丁）
 *   ⑧ fuso_libc_got()      libc 符号解析完整性（抓 PLT/GOT/符号重定向劫持）
 *
 * 设计原则（沿用 PLANNED.md「评分阈值制」铁律）：
 *   每一路都是「守卫式」——读不到 / 无权限 / 结构异常 一律返回 0（不记分），
 *   只有确凿异常才返回 1。阈值/容差刻意保守：宁可漏检，也不误杀正常玩家；
 *   真正的判定交给各关的「多路命中数 >= 阈值」来兜底。
 *
 * ★★★ 铁律（2026-10-04 真机血债）：**禁止直接解引用「别人的代码段」**。
 *   Android 10+ 把 .text 映射为 --xp（只执行、不可读），直接读会 SIGSEGV，
 *   整个 App 开箱即闪退（KL26/KL27 首日翻车根因）。任何「内存 vs 磁盘代码比对」
 *   必须走 fuso_read_code()（内部用 /proc/self/mem + pread64 内核态拷贝）。
 *   详见下方 fuso_read_code 注释。
 *
 * 注意（SKILL 坑位①）：本文件注释里禁止出现能提前闭合块注释的字符组合；
 * 需要写进程 task 目录时用 <tid> 代称。
 */

#ifndef FUSO_PROBE_H
#define FUSO_PROBE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>

/* ------------------------------------------------------------------
 * 可调阈值（各关可在 include 之前 #define 覆盖）
 * ------------------------------------------------------------------ */
#ifndef FUSO_DIRTY_KB
/* file-backed 可执行段私有脏页超过该值视为异常（kB，默认 16 = 4 页） */
#define FUSO_DIRTY_KB 16
#endif

#ifndef FUSO_TRAMP_MIN
/* 代码岛内 ARM64 跳板序列最少命中数 */
#define FUSO_TRAMP_MIN 4
#endif

#ifndef FUSO_TRAMP_MAXSCAN
/* 单个代码岛最多扫描字节数（防超大段拖慢加载期） */
#define FUSO_TRAMP_MAXSCAN (1024 * 1024)
#endif

#ifndef FUSO_SCAN_WIN
/* libc 代码段采样窗口个数 */
#define FUSO_SCAN_WIN 8
#endif

#ifndef FUSO_SCAN_LEN
/* 每个采样窗口字节数 */
#define FUSO_SCAN_LEN 256
#endif

/* ------------------------------------------------------------------
 * 宿主编译兼容：Windows/mingw 没有 pread（仅本地验证用，不影响真机）。
 * 真机（__ANDROID__）直接用 pread；宿主退化为 lseek + read。
 * ------------------------------------------------------------------ */
#if defined(__ANDROID__)
#define FUSO_PREAD pread
#else
static inline ssize_t fuso_host_pread(int fd, void *buf, size_t n, off_t off) {
    if (lseek(fd, off, SEEK_SET) == (off_t)-1) return (ssize_t)-1;
    return read(fd, buf, n);
}
#define FUSO_PREAD fuso_host_pread
#endif

/* ------------------------------------------------------------------
 * 小端读取（Android 设备均为 LE；ELF 头 EI_DATA 也按 LE 处理）
 * ------------------------------------------------------------------ */
static inline uint16_t fuso_rd16(const unsigned char *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline uint32_t fuso_rd32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint64_t fuso_rd64(const unsigned char *p) {
    return (uint64_t)fuso_rd32(p) | ((uint64_t)fuso_rd32(p + 4) << 32);
}

/* ==================================================================
 * 安全读取「非本模块」的代码/数据 —— ★★ 必读，踩过坑 ★★
 *
 * Android 10 起，链接器把 .text 映射为 --xp（只执行、**不可读**）：
 *     r--p  ...  /apex/.../bionic/libc.so
 *     --xp  ...  /apex/.../bionic/libc.so      <-- 代码段在这里
 * 直接解引用这种地址会立刻 SIGSEGV：
 *     signal 11 (SIGSEGV), code 2 (SEGV_ACCERR)
 *     Cause: execute-only (no-read) memory access error; likely due to data in .text.
 * （2026-10-04 KL26/KL27 首次真机开箱即闪退，根因就是 fuso_libc_prologue()
 *   对 libc 代码段做 memcmp(sym, disk, 16)，命中 PC 处指令为 `ldp x9,x10,[x21]`。）
 *
 * 正解：改走 /proc/self/mem + pread64 —— 内核态拷贝，绕过用户态读权限。
 *   真机实测（小米8 / Android 10 / libc 代码段 --xp）：
 *     直接指针读   → SIGSEGV
 *     /proc/self/mem → n=16, ff 03 04 d1 f3 73 00 f9 ...  ✅
 *   mprotect 补 PROT_READ 行不通：--xp 映射的 VM_MAYREAD 未置位，内核会拒绝。
 *
 * 守卫语义：读不到就返回 0（不记分、不判检出），绝不冒险解引用。
 * ================================================================== */

/* addr..addr+n 是否完整落在某个「可读(r)」VMA 内 */
static inline int fuso_is_readable(uintptr_t addr, size_t n) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[512];
    uintptr_t end = addr + n;
    int ok = 0;

    while (fgets(line, sizeof(line), f)) {
        unsigned long s = 0, e = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &s, &e, perms) < 3) continue;
        if (addr >= (uintptr_t)s && end <= (uintptr_t)e) {
            ok = (strchr(perms, 'r') != NULL);
            break;
        }
    }
    fclose(f);
    return ok;
}

/* 安全读：先 /proc/self/mem（可读 --xp 代码段），失败再退回「可读 VMA 直拷」 */
static inline int fuso_read_code(const void *addr, void *out, size_t n) {
    if (!addr || !out || n == 0) return 0;

    int fd = open("/proc/self/mem", O_RDONLY);
    if (fd >= 0) {
#if defined(__ANDROID__)
        /* 32 位 ABI 下 off_t 仅 32 位，必须用 pread64 才能寻址 >2GB 的地址 */
        ssize_t got = pread64(fd, out, n, (off64_t)(uintptr_t)addr);
#else
        ssize_t got = read(fd, out, n);   /* 宿主无 /proc/self/mem，仅语法占位 */
#endif
        close(fd);
        if (got == (ssize_t)n) return 1;
    }

    if (fuso_is_readable((uintptr_t)addr, n)) {
        memcpy(out, addr, n);
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------
 * /proc/self/maps|smaps 行解析
 *   头行形如：  7f8a1000-7f8a2000 r-xp 00000000 00:00 0  /path/to/lib.so
 *   无路径时第 6 列缺省（匿名映射）。
 * ------------------------------------------------------------------ */
struct fuso_map_ent {
    unsigned long start;
    unsigned long end;
    char perms[8];
    char path[256];
    int  has_path;   /* 第 6 列存在（含 [anon:...] / [vdso] 等 VMA 名） */
};

static inline void fuso_parse_map_line(const char *line, struct fuso_map_ent *e) {
    unsigned long off = 0, ino = 0;
    char dev[32] = {0}, path[256] = {0};

    e->start = e->end = 0;
    memset(e->perms, 0, sizeof(e->perms));
    memset(e->path, 0, sizeof(e->path));
    e->has_path = 0;

    if (sscanf(line, "%lx-%lx %7s %lx %31s %lu %255s",
               &e->start, &e->end, e->perms, &off, dev, &ino, path) >= 7) {
        snprintf(e->path, sizeof(e->path), "%s", path);
        e->has_path = 1;
    }
}

static inline int fuso_is_exec(const struct fuso_map_ent *e) {
    return strchr(e->perms, 'x') != NULL;
}

/* ==================================================================
 * ③ 可执行段私有脏页
 *   只统计「有绝对路径的 file-backed 可执行段」（so 的 .text）的
 *   Private_Dirty。正常情况只读代码段不会被 COW，Private_Dirty 近 0；
 *   inline hook 改写某个 so / libc 的代码会把对应页写脏。
 *   ——只看 file-backed 段，天然排除 ART JIT 等匿名代码缓存。
 * ================================================================== */
static inline int fuso_smaps_dirty(void) {
    FILE *f = fopen("/proc/self/smaps", "r");
    if (!f) return 0;

    char line[512];
    int in_exec = 0, is_file = 0;
    long dirty = 0, worst = 0;
    struct fuso_map_ent e;

    while (fgets(line, sizeof(line), f)) {
        if (isxdigit((unsigned char)line[0]) && strchr(line, '-') != NULL) {
            /* 新映射头行：先把上一段的统计收口 */
            if (in_exec && is_file && dirty > worst) worst = dirty;
            dirty = 0;
            fuso_parse_map_line(line, &e);
            in_exec = fuso_is_exec(&e);
            is_file = (e.has_path && e.path[0] == '/');
        } else if (in_exec && strncmp(line, "Private_Dirty:", 14) == 0) {
            dirty = strtol(line + 14, NULL, 10);
        }
    }
    if (in_exec && is_file && dirty > worst) worst = dirty;
    fclose(f);

    return (worst > FUSO_DIRTY_KB) ? 1 : 0;
}

/* ==================================================================
 * ④ 无名可执行映射（可疑代码岛）
 *   正常 App 的可执行映射都带 VMA 名——[vdso]/[vvar]/[anon:...] 等，
 *   第 6 列非空。完全无名（无第 6 列）的 r-x 段极罕见；
 *   Frida / 注入器用 mmap(MAP_ANONYMOUS) 落代码时常常不设名字。
 * ================================================================== */
static inline int fuso_anon_exec(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[512];
    int cnt = 0;
    struct fuso_map_ent e;

    while (fgets(line, sizeof(line), f) && cnt < 8) {
        fuso_parse_map_line(line, &e);
        if (!fuso_is_exec(&e)) continue;
        if (e.has_path) continue;          /* 有 VMA 名/路径 → 排除 */
        if (e.end <= e.start) continue;
        cnt++;
    }
    fclose(f);

    return (cnt >= 1) ? 1 : 0;
}

/* ==================================================================
 * ⑤ ARM64 跳板扫描
 *   在「无名可执行段」里扫 LDR X16/17,[PC,#imm] 与 BR X16/17 序列。
 *   Frida Interceptor 的 trampoline 正是这套形态；正常代码不会成簇出现。
 *   非 ARM64 平台不适用（返回 0）。
 * ================================================================== */
static inline int fuso_trampoline(void) {
#if defined(__aarch64__)
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[512];
    int hits = 0;
    struct fuso_map_ent e;

    while (fgets(line, sizeof(line), f) && hits < FUSO_TRAMP_MIN) {
        fuso_parse_map_line(line, &e);
        if (!fuso_is_exec(&e)) continue;
        if (e.has_path) continue;          /* 仅扫无名代码岛 */
        if (e.end <= e.start) continue;

        unsigned long len = e.end - e.start;
        if (len > FUSO_TRAMP_MAXSCAN) len = FUSO_TRAMP_MAXSCAN;

        /* ★ 守卫：只扫「可读」的代码岛。Android 10+ 存在 --xp 只执行不可读的
         *   匿名段（如 JIT 代码缓存），直接解引用必崩。读不到就跳过。 */
        if (!fuso_is_readable((uintptr_t)e.start, (size_t)len)) continue;

        const unsigned char *base = (const unsigned char *)e.start;
        for (unsigned long off = 0; off + 4 <= len; off += 4) {
            uint32_t insn = fuso_rd32(base + off);
            uint32_t rt = insn & 0x1Fu;

            /* LDR Xt, label  (opc=01, 011000, imm19, Rt) */
            if ((insn & 0xFF000000u) == 0x58000000u && (rt == 16u || rt == 17u)) {
                hits++;
            /* BR Xt */
            } else if ((insn & 0xFFFFFC1Fu) == 0xD61F0000u) {
                uint32_t rn = (insn >> 5) & 0x1Fu;
                if (rn == 16u || rn == 17u) hits++;
            }
            if (hits >= FUSO_TRAMP_MIN) break;
        }
    }
    fclose(f);

    return (hits >= FUSO_TRAMP_MIN) ? 1 : 0;
#else
    return 0;   /* 32 位 ARM / x86 宿主不适用 */
#endif
}

/* ------------------------------------------------------------------
 * libc 定位（用 dlsym+dladdr 反查，拿路径与加载基址）
 * ------------------------------------------------------------------ */
struct fuso_lib {
    char path[512];
    uint64_t base;
    int found;
};

static inline int fuso_find_libc(struct fuso_lib *lib) {
    static const char *PROBE[] = { "open", "read", "connect", NULL };

    lib->found = 0;
    lib->base = 0;
    lib->path[0] = '\0';

    for (int i = 0; PROBE[i]; i++) {
        void *sym = dlsym(RTLD_DEFAULT, PROBE[i]);
        if (!sym) continue;
        Dl_info di;
        if (!dladdr(sym, &di)) continue;
        if (!di.dli_fname || !strstr(di.dli_fname, "libc.so")) continue;
        snprintf(lib->path, sizeof(lib->path), "%s", di.dli_fname);
        lib->base = (uint64_t)(uintptr_t)di.dli_fbase;
        lib->found = 1;
        return 1;
    }
    return 0;
}

/* 读磁盘 ELF 头（64 字节），成功返回 1，is64 输出 1/0 */
static inline int fuso_read_ehdr(int fd, unsigned char *eh, int *is64) {
    if (read(fd, eh, 64) != 64) return 0;
    if (!(eh[0] == 0x7f && eh[1] == 'E' && eh[2] == 'L' && eh[3] == 'F')) return 0;
    *is64 = (eh[4] == 2) ? 1 : 0;
    return 1;
}

/* 把「相对 libc 基址的偏移 rel」映射到文件偏移并读取 n 字节 */
static inline int fuso_read_disk_rel(int fd, const unsigned char *eh, int is64,
                                     uint64_t rel, unsigned char *out, size_t n) {
    uint64_t phoff;
    uint16_t phentsize, phnum;

    if (is64) {
        phoff     = fuso_rd64(eh + 32);
        phentsize = fuso_rd16(eh + 54);
        phnum     = fuso_rd16(eh + 56);
    } else {
        phoff     = fuso_rd32(eh + 28);
        phentsize = (uint16_t)fuso_rd16(eh + 42);
        phnum     = (uint16_t)fuso_rd16(eh + 44);
    }
    if (phoff == 0 || phentsize == 0 || phnum == 0 || phnum > 256) return 0;

    for (uint16_t i = 0; i < phnum; i++) {
        unsigned char ph[64];
        if (phentsize > sizeof(ph)) return 0;
        if (FUSO_PREAD(fd, ph, phentsize, (off_t)(phoff + (uint64_t)i * phentsize)) != (ssize_t)phentsize)
            return 0;

        uint32_t type;
        uint64_t off, vaddr, filesz;
        if (is64) {
            type   = fuso_rd32(ph + 0);
            off    = fuso_rd64(ph + 8);
            vaddr  = fuso_rd64(ph + 16);
            filesz = fuso_rd64(ph + 32);
        } else {
            type   = fuso_rd32(ph + 0);
            off    = fuso_rd32(ph + 4);
            vaddr  = fuso_rd32(ph + 8);
            filesz = fuso_rd32(ph + 16);
        }
        if (type != 1u) continue;                      /* 仅 PT_LOAD */
        if (rel >= vaddr && rel + n <= vaddr + filesz) {
            off_t at = (off_t)(off + (rel - vaddr));
            return FUSO_PREAD(fd, out, n, at) == (ssize_t)n;
        }
    }
    return 0;
}

/* 取 libc 第一个可执行 PT_LOAD 段（vaddr/filesz），供采样校验用 */
static inline int fuso_libc_text(int fd, const unsigned char *eh, int is64,
                                 uint64_t *text_vaddr, uint64_t *text_size) {
    uint64_t phoff;
    uint16_t phentsize, phnum;

    if (is64) {
        phoff     = fuso_rd64(eh + 32);
        phentsize = fuso_rd16(eh + 54);
        phnum     = fuso_rd16(eh + 56);
    } else {
        phoff     = fuso_rd32(eh + 28);
        phentsize = (uint16_t)fuso_rd16(eh + 42);
        phnum     = (uint16_t)fuso_rd16(eh + 44);
    }
    if (phoff == 0 || phentsize == 0 || phnum == 0 || phnum > 256) return 0;

    for (uint16_t i = 0; i < phnum; i++) {
        unsigned char ph[64];
        if (phentsize > sizeof(ph)) return 0;
        if (FUSO_PREAD(fd, ph, phentsize, (off_t)(phoff + (uint64_t)i * phentsize)) != (ssize_t)phentsize)
            return 0;

        uint32_t type, flags;
        uint64_t vaddr, filesz;
        if (is64) {
            type   = fuso_rd32(ph + 0);
            flags  = fuso_rd32(ph + 4);
            vaddr  = fuso_rd64(ph + 16);
            filesz = fuso_rd64(ph + 32);
        } else {
            type   = fuso_rd32(ph + 0);
            vaddr  = fuso_rd32(ph + 8);
            filesz = fuso_rd32(ph + 16);
            flags  = fuso_rd32(ph + 24);
        }
        if (type != 1u) continue;                      /* PT_LOAD */
        if (!(flags & 1u)) continue;                   /* PF_X */
        if (filesz < FUSO_SCAN_LEN * 4) continue;
        *text_vaddr = vaddr;
        *text_size  = filesz;
        return 1;
    }
    return 0;
}

/* ==================================================================
 * ⑥ libc 关键函数入口比对（内存 vs 磁盘）
 *   对每个关键函数：dlsym 拿内存地址 → dladdr 确认归属 libc →
 *   相对基址偏移 → 从磁盘 libc.so 的 PT_LOAD 取同样偏移的 16 字节 → 比对。
 *   inline hook 会替换函数入口头几字节 → 磁盘/内存不一致。
 * ================================================================== */
static inline int fuso_libc_prologue(void) {
    static const char *FUNCS[] = {
        "open", "openat", "read", "connect", "clock_gettime", NULL
    };

    int fd = -1, bad = 0, checked = 0;
    unsigned char eh[64];
    int is64 = 0;

    for (int i = 0; FUNCS[i] && !bad; i++) {
        void *sym = dlsym(RTLD_DEFAULT, FUNCS[i]);
        if (!sym) continue;

        Dl_info di;
        if (!dladdr(sym, &di)) continue;
        if (!di.dli_fname || !strstr(di.dli_fname, "libc.so")) continue;

        if (fd < 0) {
            fd = open(di.dli_fname, O_RDONLY);
            if (fd < 0) break;
            if (!fuso_read_ehdr(fd, eh, &is64)) break;
        }

        uint64_t rel = (uint64_t)(uintptr_t)sym - (uint64_t)(uintptr_t)di.dli_fbase;

        /* ★ libc 函数体在 --xp 段，禁止直接解引用；走 /proc/self/mem 安全读 */
        unsigned char disk[16];
        unsigned char mem[16];
        if (!fuso_read_disk_rel(fd, eh, is64, rel, disk, sizeof(disk))) continue;
        if (!fuso_read_code(sym, mem, sizeof(mem))) continue;

        checked++;
        if (memcmp(mem, disk, sizeof(disk)) != 0) bad = 1;
    }

    if (fd >= 0) close(fd);
    if (checked == 0) return 0;    /* 守卫：一个都没比对成功 → 不记分 */
    return bad;
}

/* ==================================================================
 * ⑦ libc 代码段多点采样比对（内存 vs 磁盘）
 *   在 libc 第一个可执行段里取 FUSO_SCAN_WIN 个等距窗口，逐个与磁盘比对。
 *   与 ⑥ 互补：⑥ 只看函数入口（抓 inline hook），⑦ 覆盖段内任意位置，
 *   能抓到不打在入口上的补丁（如 PLT stub 改写 / 尾部跳转）。
 * ================================================================== */
static inline int fuso_libc_scan(void) {
    struct fuso_lib lib;
    if (!fuso_find_libc(&lib)) return 0;

    int fd = open(lib.path, O_RDONLY);
    if (fd < 0) return 0;

    unsigned char eh[64];
    int is64 = 0;
    if (!fuso_read_ehdr(fd, eh, &is64)) { close(fd); return 0; }

    uint64_t tvaddr = 0, tsize = 0;
    if (!fuso_libc_text(fd, eh, is64, &tvaddr, &tsize)) { close(fd); return 0; }

    unsigned char mem_w[FUSO_SCAN_LEN];
    unsigned char disk_w[FUSO_SCAN_LEN];
    uint64_t span = tsize - FUSO_SCAN_LEN;
    uint64_t step = (FUSO_SCAN_WIN > 1) ? (span / (uint64_t)(FUSO_SCAN_WIN + 1)) : 0;
    int bad = 0, ok = 0;

    for (int k = 1; k <= FUSO_SCAN_WIN && !bad; k++) {
        uint64_t rel = tvaddr + step * (uint64_t)k;
        if (!fuso_read_disk_rel(fd, eh, is64, rel, disk_w, FUSO_SCAN_LEN)) continue;

        /* ★ 同样禁止直接 memcpy：libc 代码段是 --xp，只能走 /proc/self/mem */
        const void *mem = (const void *)(uintptr_t)(lib.base + rel);
        if (!fuso_read_code(mem, mem_w, FUSO_SCAN_LEN)) continue;

        ok++;
        if (memcmp(mem_w, disk_w, FUSO_SCAN_LEN) != 0) bad = 1;
    }
    close(fd);

    if (ok == 0) return 0;
    return bad;
}

/* ==================================================================
 * ⑧ libc 符号解析完整性（PLT/GOT/符号重定向劫持）
 *   对每个关键函数 dlsym 拿地址后 dladdr 反查归属：正常应指向 libc.so；
 *   若解析到别的库或无归属，说明符号解析被劫持（LD_PRELOAD / GOT 改写）。
 *   纯 inline hook 不改解析结果——那由 ⑥/⑦ 负责；⑧ 专治"换库"。
 * ================================================================== */
static inline int fuso_libc_got(void) {
    static const char *FUNCS[] = {
        "open", "openat", "read", "write", "connect",
        "clock_gettime", "gettimeofday", "pthread_create", NULL
    };

    int bad = 0, checked = 0;

    for (int i = 0; FUNCS[i] && !bad; i++) {
        void *sym = dlsym(RTLD_DEFAULT, FUNCS[i]);
        if (!sym) continue;

        Dl_info di;
        if (!dladdr(sym, &di)) continue;
        checked++;
        if (!di.dli_fname || !strstr(di.dli_fname, "libc.so")) bad = 1;
    }

    if (checked == 0) return 0;
    return bad;
}

#endif /* FUSO_PROBE_H */
