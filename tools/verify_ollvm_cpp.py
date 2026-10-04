# -*- coding: utf-8 -*-
"""
verify_ollvm_cpp.py —— 迷阵 C++ 混淆关「四条硬门槛」自动验证（SKILL 规则 48）。

用途：`.c → .cpp`（C++ OOP + 手写 OLLVM）重构后，逐关验证语义零漂移。
  ① 老 `.c`（git HEAD）与新 `.cpp` 各编一个**宿主**程序，对同一组 (page,ts)
     输出**逐字节相同**（自带 jni.h stub，C 用 (*env)->、C++ 用 env-> 两套 ABI 同构）；
  ② 新输出喂 `server.py` 的 `_kl5x_try(KEY, ...)` 必须 True、喂 `DECOY` 必须 False；
  ③ 源码里的 `KEY_B64` 解码值 == 对应 master 的 sha256 派生链；
  ④ 报告（编译告警由调用方另跑 NDK clang++ -fsyntax-only，见 SKILL 规则 48）。

用法（必须用带 fastapi 的解释器，本项目为 D:\\python39\\python.exe）：
    D:\\python39\\python.exe tools/verify_ollvm_cpp.py            # 全部
    D:\\python39\\python.exe tools/verify_ollvm_cpp.py KL51       # 单关

自带临时目录（系统 temp 下 mkdtemp），跑完自动删除并核实——不留临时文件。
退出码 0 = 全过；1 = 有失败。
"""
import os
import sys
import re
import base64
import hashlib
import shutil
import tempfile
import subprocess
import importlib.util

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GXX = os.environ.get("FDR_GXX", r"D:\mingw64\bin\g++.exe")
MINGW = ["-D__USE_MINGW_ANSI_STDIO=1"]

# ---------------------------------------------------------------------------
# 每关配置：新增 C++ 混淆关时在此加一条即可
#   c    : git 跟踪的旧 C 源码（作基线，用 git show HEAD: 抽取）
#   cpp  : 新 C++ 源码（相对项目根）
#   fe/fs: JNI 导出的两个函数（enc / sign 各一，对应 Java 侧 nativeEnc/nativeSign*）
#   key  : server.py 里该关 master 常量名；decoy 同名 DECOY_*
#   kdrv : KEY_B64 的期望派生规则 -> (字节数, 描述, 函数 master->bytes)
# ---------------------------------------------------------------------------
def _drv_aes_mac(master):
    m = master.encode()
    return hashlib.sha256(m + b"|aes").digest()[:16] + hashlib.sha256(m + b"|mac").digest()


def _drv_sm4(master):
    return hashlib.sha256(master.encode() + b"|sm4").digest()[:16]


def _drv_kl53_aes(master):
    return hashlib.sha256(master.encode() + b"|aes").digest()[:16]


def _drv_kl53_iv(master):
    return hashlib.sha256(master.encode() + b"|iv").digest()[:16]


def _num_list(src, name):
    """从源码里抠出形如 `xxx_name[24] = { 1, 2, ... };` 的整数列表（自动剥掉行内注释）。"""
    m = re.search(re.escape(name) + r'\[[^\]]*\]\s*=\s*\{([^}]*)\}', src, re.S)
    if not m:
        raise ValueError("找不到数组 " + name)
    body = re.sub(r'/\*.*?\*/', ' ', m.group(1), flags=re.S)   # 块注释
    body = re.sub(r'//[^\n]*', ' ', body)                       # 行注释
    out = []
    for tok in body.replace("\n", " ").split(","):
        tok = tok.strip()
        if tok:
            out.append(int(tok, 0))
    return out


def _c_check_kl53(src, key):
    """KL53 用两组 XOR 字符串加密（aes 钥 0x3C / iv 0x69）藏 Base64 串。"""
    try:
        aes_enc = _num_list(src, "g_aes_b64_enc")
        iv_enc = _num_list(src, "g_iv_b64_enc")
        aes_b64 = "".join(chr(b ^ 0x3C) for b in aes_enc)
        iv_b64 = "".join(chr(b ^ 0x69) for b in iv_enc)
        want_aes = base64.b64encode(_drv_kl53_aes(key)).decode()
        want_iv = base64.b64encode(_drv_kl53_iv(key)).decode()
        return (aes_b64 == want_aes and iv_b64 == want_iv,
                "XOR{aes,iv}->b64 == sha256(master|aes|iv)[:16]")
    except Exception as e:
        return False, "parse error: %r" % e


def _c_check_kl54(src, key):
    """KL54 用魔改 Base64 码表藏 SM4 钥，须按自定义码表解码。"""
    try:
        table = re.search(r'B64_TABLE\[\]\s*=\s*\n?\s*"([^"]+)"', src).group(1)
        kb64 = re.search(r'KEY_B64\[\]\s*=\s*\n?\s*"([^"]+)"', src).group(1)
        val, bits, out = 0, 0, bytearray()
        for ch in kb64:
            i = table.find(ch)
            if i < 0:
                continue
            val = (val << 6) | i
            bits += 6
            if bits >= 8:
                bits -= 8
                out.append((val >> bits) & 0xFF)
        return (bytes(out)[:16] == _drv_sm4(key),
                "custom-b64decode(KEY_B64) == sha256(master|sm4)[:16]")
    except Exception as e:
        return False, "parse error: %r" % e


def _c_check_kl55(src, key):
    """KL55 字符串加密：真标记为 XOR 0x5A 密文（诱饵一字之差 gate→fence）。"""
    try:
        mk = _num_list(src, "MARK_ENC")
        dec = bytes(b ^ 0x5A for b in mk).decode("latin-1")
        return (dec == key), "XOR0x5A(MARK_ENC) == master(%r)" % key
    except Exception as e:
        return False, "parse error: %r" % e


def _dec_cases_kl55(srv, key):
    """造一组 nativeDecrypt 用例：2 条服务端真密文（附期望明文）+ 若干非法串。

    返回 (argv 列表, {密文: 期望明文})；非法串只参与 A 步老/新对拍，校验期望为空。
    """
    import json as _json
    sbox = srv._kl55_sbox()
    rk = srv._kl55_resp_key(key)
    iv = srv._kl55_resp_iv(key)
    cases, expect = [], {}
    for payload in ({"page": 1, "nums": [1, 2, 3]}, {"page": 7, "nums": []}):
        raw = _json.dumps(payload, separators=(",", ":")).encode()
        b64 = srv._kl55_custom_b64encode(srv._kl55_cbc_encrypt(rk, iv, raw, sbox))
        cases.append(b64)
        expect[b64] = raw.decode()
    cases += ["QUJD", "!!!bad!!!", "AAAA"]
    return cases, expect


LEVELS = {
    "KL51": dict(
        c="app/jni/fog.c", cpp="app/jni/fog.cpp",
        fe="Java_com_fatdog_reverse_FogCore_nativeEnc",
        fs="Java_com_fatdog_reverse_FogCore_nativeFlatSign",
        key="KEY_KL51", kdrv=(48, "sha256(master|aes)[:16]+sha256(master|mac)", _drv_aes_mac),
    ),
    "KL52": dict(
        c="app/jni/phantom.c", cpp="app/jni/phantom.cpp",
        fe="Java_com_fatdog_reverse_PhantomCore_nativeEnc",
        fs="Java_com_fatdog_reverse_PhantomCore_nativeSign",
        key="KEY_KL52", kdrv=(16, "sha256(master|sm4)[:16]", _drv_sm4),
    ),
    "KL53": dict(
        c="app/jni/shift.c", cpp="app/jni/shift.cpp",
        fe="Java_com_fatdog_reverse_StringGuard_nativeEnc",
        fs="Java_com_fatdog_reverse_StringGuard_nativeSign",
        key="KEY_KL53", c_check=_c_check_kl53,
    ),
    "KL54": dict(
        c="app/jni/beast.c", cpp="app/jni/beast.cpp",
        fe="Java_com_fatdog_reverse_BeastCore_nativeEnc",
        fs="Java_com_fatdog_reverse_BeastCore_nativeSign",
        key="KEY_KL54", c_check=_c_check_kl54,
    ),
    # KL55 综合收官：enc 由 nativeSign、sign 由 nativeSignHex；nativeDecrypt 做响应体解密（含 D 项对拍）。
    "KL55": dict(
        c="app/jni/gate.c", cpp="app/jni/gate.cpp",
        fe="Java_com_fatdog_reverse_GateCore_nativeSign",
        fs="Java_com_fatdog_reverse_GateCore_nativeSignHex",
        fd="Java_com_fatdog_reverse_GateCore_nativeDecrypt",
        key="KEY_KL55", c_check=_c_check_kl55, mk_dec_cases=_dec_cases_kl55,
    ),
}

SHIM = r'''
#ifndef FDR_JNI_SHIM_H
#define FDR_JNI_SHIM_H
#include <stdint.h>
#include <stddef.h>
typedef int8_t   jboolean;
typedef int32_t  jint;
typedef int64_t  jlong;
typedef uint16_t jchar;
typedef const char *jstring;
typedef void *jclass;
typedef void *jobject;
typedef struct { void *unused; } JavaVM;
#ifdef __cplusplus
struct _JNIEnv;
struct JNINativeInterface_ {
    jstring (*NewStringUTF)(_JNIEnv *, const char *);
    const char *(*GetStringUTFChars)(_JNIEnv *, jstring, jboolean *);
    void (*ReleaseStringUTFChars)(_JNIEnv *, jstring, const char *);
};
struct _JNIEnv {
    const struct JNINativeInterface_ *functions;
    jstring NewStringUTF(const char *utf) const {
        return functions->NewStringUTF(const_cast<_JNIEnv *>(this), utf);
    }
    const char *GetStringUTFChars(jstring s, jboolean *isCopy) const {
        return functions->GetStringUTFChars(const_cast<_JNIEnv *>(this), s, isCopy);
    }
    void ReleaseStringUTFChars(jstring s, const char *chars) const {
        functions->ReleaseStringUTFChars(const_cast<_JNIEnv *>(this), s, chars);
    }
};
typedef _JNIEnv JNIEnv;
#else
struct JNINativeInterface_;
typedef const struct JNINativeInterface_ *JNIEnv;
struct JNINativeInterface_ {
    jstring (*NewStringUTF)(JNIEnv *, const char *);
    const char *(*GetStringUTFChars)(JNIEnv *, jstring, jboolean *);
    void (*ReleaseStringUTFChars)(JNIEnv *, jstring, const char *);
};
#endif
#define JNIEXPORT
#define JNICALL
#define JNI_VERSION_1_6 0x00010006
#endif
'''

HARNESS = r'''
#include <cstdio>
#include "jni.h"
extern "C" {
  jstring %(fe)s(JNIEnv*, jclass, jint, jlong);
  jstring %(fs)s(JNIEnv*, jclass, jint, jlong);
  %(fdec_decl)s
  jint JNI_OnLoad(JavaVM*, void*);
}
static jstring stub_new(JNIEnv*, const char* s){ return s; }
static const char* stub_get(JNIEnv*, jstring s, jboolean*){ return s; }
static void stub_rel(JNIEnv*, jstring, const char*){ }
static const JNINativeInterface_ g_table = { stub_new, stub_get, stub_rel };
int main(int argc, char** argv){
%(onload_call)s  _JNIEnv env; env.functions = &g_table;
  struct C { int page; long long ts; } cases[] = {
    /* 真机 ts 恒为 10 位秒级时间戳（page 1-100 → 消息 18~22 字节 → KL53 的 AES-CBC 恒输出 32 字节）。
       ts 过短会让 KL53 的「固定 32 字节 hex」吃到残留 —— 系老 C 的既存边界行为，真机不可达，故用例不取极短 ts。 */
    {1,1700000000LL},{7,1700000123LL},{50,1700000001LL},{100,1234567890LL},
    {999,2147483647LL},{-123,1700000999LL},{4,-5LL}
  };
  for (unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);++i){
    int p=cases[i].page; long long t=cases[i].ts;
    const char* e = %(fe)s(&env,(jclass)0,(jint)p,(jlong)t);
    printf("ENC %%d %%lld %%s\n", p, t, e);
    const char* s = %(fs)s(&env,(jclass)0,(jint)p,(jlong)t);
    printf("SIG %%d %%lld %%s\n", p, t, s);
  }
  for (int i=1;i<argc;++i){
    jstring d = %(fdec_call)s;
    printf("DEC %%s %%s\n", argv[i], d ? d : "");
  }
  return 0;
}
'''


def _run(cmd, cwd, check=True):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True)
    if check and r.returncode != 0:
        print("  !! 命令失败:", " ".join(cmd))
        print("  " + r.stdout.decode("utf-8", "replace").replace("\n", "\n  "))
        print("  " + r.stderr.decode("utf-8", "replace").replace("\n", "\n  "))
        raise SystemExit(1)
    return r


def build_run(tmp, tag, src, is_c, fe, fs, fd=None, argv=None, onload=True):
    hp = os.path.join(tmp, "h_%s.cpp" % tag)
    open(hp, "w", encoding="utf-8").write(HARNESS % {
        "fe": fe, "fs": fs,
        "fdec_decl": ("jstring %s(JNIEnv*, jclass, jstring);" % fd) if fd else "",
        "fdec_call": ("%s(&env,(jclass)0, argv[i])" % fd) if fd else "(jstring)0",
        "onload_call": ("  JavaVM vm; JNI_OnLoad(&vm, (void*)0);\n" if onload else ""),
    })
    obj = os.path.join(tmp, tag + ".o")
    lang = "c" if is_c else "c++"
    std = "-std=c11" if is_c else "-std=c++17"
    _run([GXX, "-x", lang, std, "-c", src, "-I."] + MINGW + ["-w", "-o", obj], cwd=tmp)
    exe = os.path.join(tmp, "t_%s.exe" % tag)
    _run([GXX, "-std=c++17"] + MINGW + ["-static", hp, obj, "-o", exe], cwd=tmp)
    r = subprocess.run([exe] + list(argv or []), cwd=tmp, capture_output=True)
    if r.returncode != 0:
        print("  !! 宿主程序崩溃", tag, "rc=%d" % r.returncode)
        raise SystemExit(1)
    return r.stdout.decode("utf-8", "replace").strip()


def parse(txt):
    d = {}
    for line in txt.splitlines():
        p = line.strip().split(" ", 3)
        if len(p) == 4 and p[0] in ("ENC", "SIG"):
            d.setdefault((p[1], p[2]), {})[p[0]] = p[3]
    return d


def parse_dec(txt):
    d = {}
    for line in txt.splitlines():
        p = line.strip().split(" ", 2)
        if len(p) == 3 and p[0] == "DEC":
            d[p[1]] = p[2]
    return d


def verify_level(tmp, srv, name, cfg, failures):
    print("\n=== %s ===" % name)
    # 0) 基线：从 git HEAD 抽旧 C
    rel = cfg["c"]
    raw = subprocess.run(["git", "show", "HEAD:" + rel], cwd=ROOT, capture_output=True).stdout
    if not raw:
        print("  !! git HEAD 里没有 %s（无法对拍基线）" % rel)
        failures.append(name + ":no-baseline")
        return
    base = os.path.join(tmp, os.path.basename(rel))
    open(base, "wb").write(raw)
    print("  基线 %-28s %6d bytes" % (rel, len(raw)))

    # 0b) 可选：构造 nativeDecrypt 对拍用例（关卡提供 mk_dec_cases 钩子）
    fd = cfg.get("fd")
    argv, dec_expect = [], {}
    if fd and "mk_dec_cases" in cfg:
        argv, dec_expect = cfg["mk_dec_cases"](srv, getattr(srv, cfg["key"]))

    # A) 算法等价：老 C vs 新 C++ 在「不调 JNI_OnLoad」下逐字节一致
    #    （两侧 constructor 照常执行；JNI_OnLoad 的副作用不参与 —— 确保算法核心在同一状态下执行。
    #     这一步只管「重构有没有改算法」，不管初始化时序。）
    o_old = build_run(tmp, name + "_old", base, True, cfg["fe"], cfg["fs"], onload=False)
    o_newa = build_run(tmp, name + "_new", os.path.join(ROOT, cfg["cpp"]), False, cfg["fe"], cfg["fs"], onload=False)
    ok_a = (o_old == o_newa)
    print("  A 老C/新C++ 算法等价(不调 JNI_OnLoad) :", ok_a)
    if not ok_a:
        import difflib
        print("\n".join(difflib.unified_diff(o_old.split("\n"), o_newa.split("\n"),
                                            "old", "new", lineterm="")))
        failures.append(name + ":A")

    # A2) 真机完整加载路径：调 JNI_OnLoad（模拟 so 真实加载时序）。新 C++ 必须正确。
    o_new = build_run(tmp, name + "_rt", os.path.join(ROOT, cfg["cpp"]), False, cfg["fe"], cfg["fs"], fd, argv, onload=True)

    # B) server.py 端到端验签
    tryfn = getattr(srv, "_%s_try" % name.lower())
    key = getattr(srv, cfg["key"])
    decoy = getattr(srv, "DECOY_" + cfg["key"].split("_", 1)[1])[0]
    d = parse(o_new)
    n = ok = dec = 0
    fails_b = []
    for (p, t), v in d.items():
        pi, ti = int(p), int(t)
        if pi < 1 or ti < 0:
            continue  # server 只接受 page>=1, ts>=0；负值仅用于 A 步对拍
        n += 1
        if tryfn(key, pi, ti, v["ENC"], v["SIG"]):
            ok += 1
        else:
            fails_b.append((pi, ti, "real-rejected"))
        if not tryfn(decoy, pi, ti, v["ENC"], v["SIG"]):
            dec += 1
        else:
            fails_b.append((pi, ti, "decoy-accepted"))
    ok_b = (ok == n and dec == n and n > 0)
    print("  B 服务端验签 真钥 %d/%d 诱饵被拒 %d/%d :" % (ok, n, dec, n), ok_b)
    if fails_b:
        print("    失败明细:", fails_b)
    if not ok_b:
        failures.append(name + ":B")

    # D) nativeDecrypt 端到端（可选）：服务端真密文 → 宿主解密 == 原始明文
    if dec_expect:
        dd = parse_dec(o_new)
        bad = [k for k, v in dec_expect.items() if dd.get(k) != v]
        ok_d = (not bad)
        print("  D nativeDecrypt 服务端密文→明文 %d/%d :" % (len(dec_expect) - len(bad), len(dec_expect)), ok_d)
        if bad:
            print("    失败用例(前3):", bad[:3])
        if not ok_d:
            failures.append(name + ":D")

    # C) 藏钥检查（默认按 KEY_B64 标准解码；关卡可提供 c_check 自定义）
    src = open(os.path.join(ROOT, cfg["cpp"]), encoding="utf-8").read()
    if "c_check" in cfg:
        ok_c, desc = cfg["c_check"](src, key)
    else:
        mt = re.search(r'KEY_B64\[\]\s*=\s*\n?\s*"([^"]+)"', src)
        want_len, desc, drv = cfg["kdrv"]
        ok_c = bool(mt) and (base64.b64decode(mt.group(1)) == drv(key)) and len(drv(key)) == want_len
    print("  C 藏钥 %s :" % desc, ok_c)
    if not ok_c:
        failures.append(name + ":C")


def main():
    only = [a.upper() for a in sys.argv[1:] if not a.startswith("-")]
    want = [k for k in LEVELS if not only or k in only]
    if not want:
        print("没有匹配的关卡：", only, " 可选:", list(LEVELS))
        return 1

    spec = importlib.util.spec_from_file_location("fdr_server", os.path.join(ROOT, "server.py"))
    srv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(srv)

    tmp = tempfile.mkdtemp(prefix="fdr_ollvm_cpp_")
    failures = []
    try:
        open(os.path.join(tmp, "jni.h"), "w", encoding="utf-8").write(SHIM)
        for name in want:
            verify_level(tmp, srv, name, LEVELS[name], failures)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        print("\n临时目录已清理:", tmp, "->", "不存在" if not os.path.exists(tmp) else "!! 仍存在")

    print("\n===== 汇总 =====")
    if failures:
        print("  FAIL:", ", ".join(failures))
        return 1
    print("  全部通过（A 逐字节 + B 验签 + C 藏钥）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
