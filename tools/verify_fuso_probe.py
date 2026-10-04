#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_fuso_probe.py — 扶桑树「注入痕迹检测关」KL26/KL27/KL28 验证工具（表驱动）

KL28 为 C++ OOP 实现（snow.cpp）：工具按源码扩展名自动选编译器（.c→gcc/-std=c11，
.cpp→g++/-std=c++17），stub jni.h 用 #ifdef __cplusplus 同时提供 C 与 C++ 两套 JNIEnv。

一次性核对三件事：

  A. JNI 符号 ↔ Java `native` 声明 一一对应
       .c 里 `Java_com_fatdog_reverse_<Bridge>_<method>` 集合
       ==      `<Bridge>.java` 里 `native <type> <method>(...)` 集合

  B. 宿主自测（stub jni.h / dlfcn.h，mingw gcc 编译 exe 直接跑）
       （宿主编译时 fuso_probe.h 依赖的 /proc 不存在、dlsym 全空 →
         所有注入痕迹信号天然返回 0，正好用来验「加载期机制 + 算法」。）
       ① 干净态（默认阈值）：`phase == 1` 且 `answer == SEED 真值`
       ② 阈值覆盖为 0（-D<THRESH>_THRESHOLD=0）：`phase == 2`
          且 `answer == "DETECTED_FRIDA_LOCKED_ANSWER"`（锁定分支实证）

  C. LCG 复刻对拍：宿主编出的 answer 与 Python 复刻逐字节相同

用法：
    python tools/verify_fuso_probe.py
"""

import os
import re
import sys
import shutil
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
JNI = os.path.join(ROOT, "app", "jni")
SRC = os.path.join(ROOT, "app", "src", "com", "fatdog", "reverse")

# ------------------------------------------------------------------
# 关卡表（新增检测关只需加一条）
# ------------------------------------------------------------------
LEVELS = [
    {
        "name": "KL26",
        "src": "dusk.c",
        "bridge": "Sk",
        "seed": 20280720,
        "thresh_macro": "KL26_THRESHOLD",
        "sig_count": 6,
        "answer": "8ac8cc07027b4d6d8bf9cd8003454e71",
    },
    {
        "name": "KL27",
        "src": "veil.c",
        "bridge": "Vk27",
        "seed": 20280721,
        "thresh_macro": "KL27_THRESHOLD",
        "sig_count": 7,
        "answer": "4cc08a01cc4402bc4da28b32cdcd0386",
    },
    {
        # KL28 是 C++ OOP 实现（snow.cpp）：宿主用 g++ 编译，stub jni.h 走 C++ 分支
        "name": "KL28",
        "src": "snow.cpp",
        "bridge": "Wk28",
        "seed": 20280722,
        "thresh_macro": "KL28_THRESHOLD",
        "sig_count": 8,
        "answer": "8399c59f0bec469884fec6510ce347fc",
    },
]

LOCKED = "DETECTED_FRIDA_LOCKED_ANSWER"

# ------------------------------------------------------------------
# 宿主工具链
# ------------------------------------------------------------------
def find_cc():
    """C 编译器（KL26/27 等 .c 源）。"""
    cands = [
        r"D:\mingw64\bin\gcc.exe",
        shutil.which("gcc"),
        shutil.which("cc"),
    ]
    for c in cands:
        if c and os.path.exists(c):
            return c
    return None


def find_cxx():
    """C++ 编译器（KL28 snow.cpp 等 .cpp 源）。"""
    cands = [
        r"D:\mingw64\bin\g++.exe",
        shutil.which("g++"),
        shutil.which("c++"),
    ]
    for c in cands:
        if c and os.path.exists(c):
            return c
    return None


def compiler_for(level):
    return find_cxx() if level["src"].endswith(".cpp") else find_cc()


# ------------------------------------------------------------------
# 桩头文件（宿主自测用）
# ------------------------------------------------------------------
STUB_JNI = r"""
#ifndef _STUB_JNI_H
#define _STUB_JNI_H
#include <stddef.h>
typedef void *jobject;
typedef void *jclass;
typedef void *jstring;
typedef int   jint;
#ifdef __cplusplus
/* C++ 源（如 snow.cpp）用 env->NewStringUTF 两套 ABI：首成员必须是 functions 表指针 */
struct _JNIEnv;
struct JNINativeInterface_ {
    void *reserved[16];
    jstring (*NewStringUTF)(_JNIEnv *, const char *);
};
struct _JNIEnv {
    const struct JNINativeInterface_ *functions;
    jstring NewStringUTF(const char *utf) const {
        return functions->NewStringUTF(const_cast<_JNIEnv *>(this), utf);
    }
};
typedef _JNIEnv JNIEnv;
#else
struct JNINativeInterface_;
typedef const struct JNINativeInterface_ *JNIEnv;
struct JNINativeInterface_ {
    void *reserved[16];
    jstring (*NewStringUTF)(JNIEnv *, const char *);
};
#endif
#define JNIEXPORT
#define JNICALL
#define JNI_ERR (-1)
#define JNI_VERSION_1_6 0x00010006
#endif
"""

STUB_DLFCN = r"""
#ifndef _STUB_DLFCN_H
#define _STUB_DLFCN_H
#define RTLD_LAZY 1
#define RTLD_NOW  2
#define RTLD_DEFAULT ((void *)0)
typedef struct {
    const char *dli_fname;
    void       *dli_fbase;
    const char *dli_sname;
    void       *dli_saddr;
} Dl_info;
static inline void *dlopen(const char *f, int m) { (void)f; (void)m; return (void *)1; }
static inline void *dlsym(void *h, const char *s) { (void)h; (void)s; return (void *)0; }
static inline int   dlclose(void *h) { (void)h; return 0; }
static inline int   dladdr(const void *a, Dl_info *i) {
    (void)a;
    if (i) { i->dli_fname = 0; i->dli_fbase = 0; i->dli_sname = 0; i->dli_saddr = 0; }
    return 0;
}
#endif
"""

HARNESS_TMPL = r"""
#include <stdio.h>
#include "%(src)s"
int main(void) {
    printf("phase=%%d\n", (int)g_load_phase);
    printf("score=%%d\n", g_load_score);
    printf("detect=%%d\n", detect_frida());
    printf("answer=%%s\n", compute_answer());
    return 0;
}
"""


# ------------------------------------------------------------------
# 工具函数
# ------------------------------------------------------------------
def read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def lcg_ans(seed):
    MASK = 0xFFFFFFFF
    h = seed
    h = (h * 1103515245 + 12345) & MASK
    h = (h ^ ((h << 13) & MASK)) & MASK
    h ^= h >> 17
    h = (h ^ ((h << 5) & MASK)) & MASK
    h ^= (seed * 214013 + 2531011) & MASK
    h &= MASK
    out = []
    for i in range(32):
        out.append("0123456789abcdef"[(h >> ((i % 4) * 4)) & 0xF])
        h = (h * 1664525 + 1013904223) & MASK
    return "".join(out)


def jni_exports(path, bridge):
    pat = re.compile(r"Java_com_fatdog_reverse_" + re.escape(bridge) + r"_(\w+)\s*\(")
    return set(pat.findall(read(path)))


def java_natives(path):
    pat = re.compile(r"\bnative\s+[\w\[\]]+\s+(\w+)\s*\(")
    return set(pat.findall(read(path)))


# ------------------------------------------------------------------
# 检查项
# ------------------------------------------------------------------
def check_jni(level, ctx):
    src = os.path.join(JNI, level["src"])
    jav = os.path.join(SRC, level["bridge"] + ".java")
    exp = jni_exports(src, level["bridge"])
    nat = java_natives(jav)
    ok = (exp == nat) and len(exp) > 0
    ctx[level["name"] + ".jni"] = ok
    print("  [%s] JNI 符号 ↔ Java 声明 : %s" %
          ("PASS" if ok else "FAIL", "%d 个" % len(exp)))
    if not ok:
        print("      .c 导出 :", sorted(exp))
        print("      .java   :", sorted(nat))
        print("      仅 .c   :", sorted(exp - nat))
        print("      仅 .java:", sorted(nat - exp))
    return ok


def build_harness(cc, tmp, level, extra_defs=None):
    is_cpp = level["src"].endswith(".cpp")
    ext = ".cpp" if is_cpp else ".c"
    std = "-std=c++17" if is_cpp else "-std=c11"
    harn = os.path.join(tmp, "harness_%s%s" % (level["name"], ext))
    with open(harn, "w", encoding="utf-8") as f:
        f.write(HARNESS_TMPL % {"src": level["src"]})
    exe = os.path.join(tmp, "harness_%s.exe" % level["name"])
    cmd = [cc, std, "-Wall", "-Wextra",
           "-I" + tmp, "-I" + JNI]
    if extra_defs:
        cmd += extra_defs
    cmd += [harn, "-o", exe]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("      编译失败:\n", (r.stdout + r.stderr)[:1500])
        return None
    if (r.stdout + r.stderr).strip():
        print("      编译告警:\n", (r.stdout + r.stderr)[:800])
    return exe


def run_harness(exe):
    r = subprocess.run([exe], capture_output=True, text=True)
    out = {}
    for line in r.stdout.splitlines():
        line = line.strip()
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def check_host(cc, tmp, level, ctx):
    ok_all = True

    # ① 干净态
    exe = build_harness(cc, tmp, level)
    if exe is None:
        ctx[level["name"] + ".host"] = False
        return False
    o = run_harness(exe)
    clean_ok = (o.get("phase") == "1" and o.get("answer") == level["answer"]
                and o.get("detect") == "0")
    print("  [%s] 干净态  : phase=%s score=%s detect=%s answer=%s"
          % ("PASS" if clean_ok else "FAIL", o.get("phase"), o.get("score"),
             o.get("detect"), o.get("answer")))
    ok_all &= clean_ok

    # ② 阈值覆盖为 0 → 锁定分支
    exe0 = build_harness(cc, tmp, level,
                         extra_defs=["-D%s=0" % level["thresh_macro"]])
    if exe0 is None:
        ctx[level["name"] + ".host"] = False
        return False
    o0 = run_harness(exe0)
    lock_ok = (o0.get("phase") == "2" and o0.get("answer") == LOCKED
               and o0.get("detect") == "1")
    print("  [%s] 阈值=0  : phase=%s detect=%s answer=%s"
          % ("PASS" if lock_ok else "FAIL", o0.get("phase"),
             o0.get("detect"), o0.get("answer")))
    ok_all &= lock_ok

    ctx[level["name"] + ".host"] = ok_all
    return ok_all


def check_answer(level, ctx):
    py = lcg_ans(level["seed"])
    ok = (py == level["answer"])
    ctx[level["name"] + ".answer"] = ok
    print("  [%s] LCG 复刻 : %s (seed=%d)"
          % ("PASS" if ok else "FAIL", py if ok else py + " != " + level["answer"],
             level["seed"]))
    return ok


# ------------------------------------------------------------------
# main
# ------------------------------------------------------------------
def main():
    print("宿主编译器 : C=%s  C++=%s" % (find_cc() or "未找到", find_cxx() or "未找到"))
    print("=" * 62)

    tmp = tempfile.mkdtemp(prefix="fusoprobe_")
    results = []
    try:
        with open(os.path.join(tmp, "jni.h"), "w", encoding="utf-8") as f:
            f.write(STUB_JNI)
        with open(os.path.join(tmp, "dlfcn.h"), "w", encoding="utf-8") as f:
            f.write(STUB_DLFCN)

        for lv in LEVELS:
            print("[%s]" % lv["name"])
            ctx = {}
            cc = compiler_for(lv)
            if cc:
                check_host(cc, tmp, lv, ctx)
            else:
                print("  (跳过宿主自测：无编译器)")
            check_jni(lv, ctx)
            check_answer(lv, ctx)
            results.append(ctx)
            print("-" * 62)

        # 汇总
        all_ok = True
        for lv, ctx in zip(LEVELS, results):
            fails = [k for k, v in ctx.items() if not v]
            all_ok &= not fails
            print("%s : %s" % (lv["name"], "ALL PASS" if not fails else ("FAIL " + str(fails))))
        print("=" * 62)
        print("总判定 :", "ALL PASS" if all_ok else "HAS FAILURE")
        return 0 if all_ok else 1
    finally:
        # 临时目录用完即删并核实（本环境 rm 会静默失效，故走 shutil）
        shutil.rmtree(tmp, ignore_errors=True)
        print("临时目录已清理 :", not os.path.exists(tmp), "->", tmp)


if __name__ == "__main__":
    sys.exit(main())
