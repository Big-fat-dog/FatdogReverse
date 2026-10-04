# -*- coding: utf-8 -*-
"""Native大陆 L48-L53「每关 10 个 so」改造生成器。

做六件事（幂等，可重复运行）：
  1. 12 个直白命名的 so 源文件改成无规律名（native48 -> badger 等），并同步文件内自引用；
  2. app/src 下 Java 文件里的旧 so 名 token 同步替换（loadLibrary / 注释）；
  3. 生成 48 个干扰 so 的 .cpp；
  4. 给 3 个「已存在的业务 so」(quota/registry/customs) 补挂 RegisterNatives 注册；
  5. 改写 app/jni/Android.mk 的 L48-L53 段（12 改名 + 48 新增，共 60 个模块）；
  6. 改写三个装载点 AppInit / MainActivity / WarmUp（每处 20 个 so）。

设计约束（见 SKILL 规则 46）：
  - 干扰 so 的 JNI_OnLoad 必须**防御式**：FindClass/RegisterNatives 失败一律 ExceptionClear 后
    返回 JNI_VERSION_1_6，绝不返回 JNI_ERR、绝不留下 pending exception（否则 App 启动即崩）。
  - 干扰 so 注册的方法名与真身不重名，避免覆盖真实现；桥类里对应补上 native 声明。
  - 干扰 so 方法返回**看起来合法的 hex 摘要**，玩家无法靠"返回值像不像"区分真假。
  - JNI_OnLoad 必须 `extern "C" JNIEXPORT ... JNICALL`（否则 C++ 名字修饰，加载器 dlsym 找不到）。
"""
import os
import re

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JNI = os.path.join(HERE, 'app', 'jni')
SRC = os.path.join(HERE, 'app', 'src', 'com', 'fatdog', 'reverse')

# ──────────────────────────── 事实表 ────────────────────────────

# 12 个直白 so 改名（旧模块名 -> 新模块名）；替换时长名优先
RENAMES = [
    ('native48', 'badger'),
    ('native49', 'otter'),
    ('native51h', 'turtle'),
    ('native51b', 'quota'),
    ('native51', 'shark'),
    ('native52k', 'cobra'),
    ('native52b', 'registry'),
    ('native52', 'moose'),
    ('native53c', 'viper'),
    ('native53b', 'customs'),
    ('native53', 'tapir'),
    ('native50', 'crane'),
]

LEVEL_META = {
    48: ('Bk48', 'com/fatdog/reverse/Bk48'),
    49: ('Bk49', 'com/fatdog/reverse/Bk49'),
    50: ('Bk50', 'com/fatdog/reverse/Bk50'),
    51: ('Bk51', 'com/fatdog/reverse/Bk51'),
    52: ('Bk52', 'com/fatdog/reverse/Bk52'),
    53: ('Bk53', 'com/fatdog/reverse/Bk53'),
}

# 这 3 个业务 so 已存在，只改名 + 补挂 JNI 注册，不重新生成
EXISTING_DECOYS = {'quota', 'registry', 'customs'}

# (level, module, 假方法名, 返回类型, 参数列表)   s=String i=int l=long
DECOYS = [
    (48, 'heron',    'nativeAudit',       's', []),
    (48, 'pelican',  'nativeDigest',      's', ['s']),
    (48, 'magpie',   'nativeToken',       's', ['i']),
    (48, 'walrus',   'nativeChecksum',    's', ['s']),
    (48, 'beetle',   'nativePad',         's', ['s', 'i']),
    (48, 'ledger',   'nativeEnvelope',    's', ['i', 'l']),
    (48, 'voucher',  'nativeSeal',        's', ['s']),
    (48, 'tariff',   'nativeRate',        'i', ['i', 'i']),
    (48, 'cobalt',   'nativeBlend',       's', ['s']),
    (49, 'falcon',   'nativeProbe',       's', []),
    (49, 'gecko',    'nativeMix',         's', ['s']),
    (49, 'lynx',     'nativeFingerprint', 's', ['i']),
    (49, 'hornet',   'nativeStretch',     's', ['s', 'i']),
    (49, 'payroll',  'nativeAdvance',     'l', ['i', 'i']),
    (49, 'dispatch', 'nativeRoute',       's', ['s']),
    (49, 'cargo',    'nativePack',        's', ['s']),
    (49, 'escrow',   'nativeHold',        's', ['s', 'i']),
    (49, 'quartz',   'nativeLattice',     's', ['s']),
    (50, 'ibex',     'nativeLadder',      's', ['i']),
    (50, 'koala',    'nativeWrap',        's', ['s']),
    (50, 'mink',     'nativeFade',        's', ['s', 'i']),
    (50, 'cricket',  'nativeChirp',       's', ['i', 'l']),
    (50, 'invoice',  'nativeSettle',      's', ['s']),
    (50, 'parcel',   'nativeBundle',      's', ['s']),
    (50, 'vendor',   'nativeQuote',       'i', ['s', 'i']),
    (50, 'manifest', 'nativeIndex',       's', ['s']),
    (50, 'granite',  'nativeStratum',     's', ['i']),
    (51, 'quota',    'nativeBucket',      's', ['i']),
    (51, 'newt',     'nativeShed',        's', ['s']),
    (51, 'weasel',   'nativeSlink',       's', ['s', 'i']),
    (51, 'salmon',   'nativeLeap',        's', ['i']),
    (51, 'audit',    'nativeReconcile',   's', ['s']),
    (51, 'freight',  'nativeHaul',        's', ['s', 'i']),
    (51, 'courier',  'nativeRelay',       's', ['s']),
    (51, 'bond',     'nativeCoupon',      'i', ['i', 'i']),
    (52, 'registry', 'nativeCatalog',     's', ['s']),
    (52, 'dingo',    'nativeProwl',       's', ['i']),
    (52, 'eagle',    'nativeSoar',        's', ['s']),
    (52, 'finch',    'nativeTrill',       's', ['i', 'l']),
    (52, 'retail',   'nativeMarkup',      'i', ['s', 'i']),
    (52, 'banking',  'nativeLedger',      's', ['s']),
    (52, 'fund',     'nativePool',        's', ['s']),
    (52, 'tender',   'nativeBid',         's', ['i', 'i']),
    (53, 'customs',  'nativeClear',       's', ['s']),
    (53, 'zebra',    'nativeStripe',      's', ['i']),
    (53, 'panda',    'nativeMunch',       's', ['s']),
    (53, 'lemur',    'nativeTail',        's', ['i', 'l']),
    (53, 'quail',    'nativeCovey',       's', ['i']),
    (53, 'robin',    'nativeWarbler',     's', ['s']),
    (53, 'seal',     'nativeStamp',       's', ['s', 'i']),
    (53, 'rebate',   'nativeCredit',      'i', ['i', 'i']),
]

# 三个装载点（A/B/C 三种藏法，见 SKILL 规则 46）
LOAD_GROUPS = {
    'AppInit': [48, 49],
    'MainActivity': [50, 51],
    'WarmUp': [52, 53],
}

# 每关的「真身/辅助 so」（不在 DECOYS 里的那些，装载时序上放最后）
REAL_SO = {
    48: ['badger'],
    49: ['otter'],
    50: ['crane'],
    51: ['turtle', 'shark'],   # turtle=辅助(密钥/哈希), shark=主入口
    52: ['cobra', 'moose'],
    53: ['viper', 'tapir'],
}

# 各模块 NDK 编译参数（沿用改名前原模块的设置；未列出=沿用 APP_CPPFLAGS）
MODULE_FLAGS = {
    'shark':    'LOCAL_LDLIBS := -ldl',
    'moose':    'LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti\nLOCAL_LDLIBS := -llog -ldl',
    'cobra':    'LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti\nLOCAL_LDLIBS := -llog',
    'tapir':    'LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti\nLOCAL_LDLIBS := -llog -ldl',
    'viper':    'LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti\nLOCAL_LDLIBS := -llog',
    'quota':    'LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti\nLOCAL_LDLIBS := -llog',
    'registry': 'LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti\nLOCAL_LDLIBS := -llog',
    'customs':  'LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti\nLOCAL_LDLIBS := -llog',
}

RET_DESC = {'s': 'Ljava/lang/String;', 'i': 'I', 'l': 'J'}
C_TYPE = {'s': 'jstring', 'i': 'jint', 'l': 'jlong'}


def cap(mod):
    return mod[0].upper() + mod[1:]


def salt_of(mod):
    h = 0x811C9DC5
    for ch in mod.encode('ascii'):
        h = ((h ^ ch) * 16777619) & 0xFFFFFFFF
    return h


def c_params(params):
    return ''.join(', %s a%d' % (C_TYPE[p], i) for i, p in enumerate(params))


def descriptor(params, ret):
    return '(' + ''.join(RET_DESC[p] for p in params) + ')' + RET_DESC[ret]


def words_of(mod):
    return (4, 8, 8)[len(mod) % 3]


def build_body(ns, capname, flavor, params, salt):
    lines = []
    if params:
        for i, p in enumerate(params):
            if p == 's':
                lines.append('    in += jstr_to_std(env, a%d);' % i)
            else:
                lines.append('    in += std::to_string((long long)a%d);' % i)
    else:
        lines.append('    in = "<probe>";')
    if flavor == 0:
        lines.append('    %s::%sCodec codec(%uu);' % (ns, capname, salt))
        lines.append('    in = codec.decode(codec.encode(in));')
    elif flavor == 1:
        lines.append('    %s::%sLedger ledger;' % (ns, capname))
        lines.append('    ledger.post("main", (int64_t)in.size());')
        lines.append('    ledger.post("aux", (int64_t)(in.size() ^ 0x5Au));')
        lines.append('    in += std::to_string((long long)ledger.balance("main"));')
    else:
        lines.append('    %s::%sScheduler sched;' % (ns, capname))
        lines.append('    sched.push(2, (uint32_t)in.size());')
        lines.append('    sched.push(1, (uint32_t)(in.size() + 1));')
        lines.append('    in += std::to_string((long long)sched.pop());')
    return '\n'.join(lines)


def build_ret(ret, salt, words):
    if ret == 's':
        return ('std::string hex = mix_hex(in, %uu, %d);\n'
                '    return env->NewStringUTF(hex.c_str());' % (salt, words))
    if ret == 'i':
        return 'return (jint)mix_scalar(in, %uu);' % salt
    return ('uint64_t v = (uint64_t)mix_scalar(in, %uu) * 1000003ull + (uint64_t)in.size();\n'
            '    return (jlong)v;' % salt)


# ──────────────────────────── 干扰 so 模板 ────────────────────────────

HEADER = """/*
 * lib{mod}.so — {cap} 业务模块
 *
 * 独立业务库；JNI 侧走 RegisterNatives 动态绑定。
 */

#include <jni.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <utility>
#include <functional>
#include <algorithm>

namespace {ns} {{

"""

FLAVOR_CODEC = """class {cap}Codec {{
public:
    explicit {cap}Codec(uint32_t salt) : salt_(salt) {{}}
    std::string encode(const std::string& in) const {{
        std::string out = in;
        for (size_t i = 0; i < out.size(); ++i) {{
            uint8_t k = (uint8_t)((salt_ >> ((i & 3) * 8)) & 0xFF);
            out[i] = (char)((uint8_t)((uint8_t)out[i] ^ k) + (uint8_t)(i & 0x1F));
        }}
        return out;
    }}
    std::string decode(const std::string& in) const {{
        std::string out = in;
        for (size_t i = 0; i < out.size(); ++i) {{
            uint8_t k = (uint8_t)((salt_ >> ((i & 3) * 8)) & 0xFF);
            out[i] = (char)((uint8_t)((uint8_t)out[i] - (uint8_t)(i & 0x1F)) ^ k);
        }}
        return out;
    }}
    uint32_t salt() const {{ return salt_; }}
private:
    uint32_t salt_;
}};

}} /* namespace {ns} */

"""

FLAVOR_LEDGER = """class {cap}Ledger {{
public:
    void post(const std::string& account, int64_t amount) {{
        book_.push_back(std::make_pair(account, amount));
    }}
    int64_t balance(const std::string& account) const {{
        int64_t sum = 0;
        for (size_t i = 0; i < book_.size(); ++i)
            if (book_[i].first == account) sum += book_[i].second;
        return sum;
    }}
    size_t entries() const {{ return book_.size(); }}
private:
    std::vector<std::pair<std::string, int64_t> > book_;
}};

}} /* namespace {ns} */

"""

FLAVOR_SCHED = """class {cap}Scheduler {{
public:
    void push(int priority, uint32_t task) {{
        heap_.push_back(std::make_pair(priority, task));
        std::push_heap(heap_.begin(), heap_.end(), std::greater<std::pair<int, uint32_t> >());
    }}
    uint32_t pop() {{
        if (heap_.empty()) return 0u;
        std::pop_heap(heap_.begin(), heap_.end(), std::greater<std::pair<int, uint32_t> >());
        uint32_t task = heap_.back().second;
        heap_.pop_back();
        return task;
    }}
    size_t size() const {{ return heap_.size(); }}
private:
    std::vector<std::pair<int, uint32_t> > heap_;
}};

}} /* namespace {ns} */

"""

COMMON_TAIL = """__attribute__((unused)) static std::string jstr_to_std(JNIEnv* env, jstring s) {{
    if (s == nullptr) return std::string();
    const char* c = env->GetStringUTFChars(s, nullptr);
    std::string out = (c != nullptr) ? std::string(c) : std::string();
    if (c != nullptr) env->ReleaseStringUTFChars(s, c);
    return out;
}}

__attribute__((unused)) static uint32_t mix_scalar(const std::string& in, uint32_t salt) {{
    uint32_t a = 0x811C9DC5u ^ salt;
    for (size_t i = 0; i < in.size(); ++i) {{
        a ^= (uint8_t)in[i];
        a *= 16777619u;
    }}
    uint32_t b = a ^ 0x9E3779B9u;
    b = (b << 5 | b >> 27) ^ (a + 0x27D4EB2Du);
    return b ^ (uint32_t)in.size();
}}

__attribute__((unused)) static std::string mix_hex(const std::string& in, uint32_t salt, int words) {{
    uint32_t a = 0x811C9DC5u ^ salt;
    uint32_t b = a ^ 0x9E3779B9u;
    std::string out;
    char buf[16];
    for (int i = 0; i < words; ++i) {{
        b = (b << 5 | b >> 27) ^ (a + (uint32_t)(i * 0x27D4EB2Du));
        a = (a << 13 | a >> 19) + (b ^ 0x165667B1u);
        snprintf(buf, sizeof(buf), "%08x", b);
        out += buf;
    }}
    return out;
}}

static {cret} {fn}(JNIEnv* env, jobject{params}) {{
    std::string in;
{body}
    {retstmt}
}}

static const JNINativeMethod gMethods[] = {{
    {{"{method}", "{desc}", (void*){fn}}},
}};

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {{
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK) {{
        jclass cls = env->FindClass("{fqn}");
        if (cls != nullptr) {{
            if (env->RegisterNatives(cls, gMethods, 1) != JNI_OK && env->ExceptionCheck())
                env->ExceptionClear();
        }} else if (env->ExceptionCheck()) {{
            env->ExceptionClear();
        }}
    }}
    return JNI_VERSION_1_6;
}}
"""


def gen_decoy_source(level, mod, method, ret, params):
    salt = salt_of(mod)
    capname = cap(mod)
    flavor = abs(salt) % 3
    flavor_src = (FLAVOR_CODEC, FLAVOR_LEDGER, FLAVOR_SCHED)[flavor]
    text = HEADER.format(mod=mod, cap=capname, ns=mod)
    text += flavor_src.format(cap=capname, ns=mod)
    text += COMMON_TAIL.format(
        cret=C_TYPE[ret],
        fn='j_' + method.replace('native', 'n'),
        params=c_params(params),
        body=build_body(mod, capname, flavor, params, salt),
        retstmt=build_ret(ret, salt, words_of(mod)),
        method=method,
        desc=descriptor(params, ret),
        fqn=LEVEL_META[level][1],
    )
    return text


def existing_decoy_snippet(level, mod, method, ret, params):
    """给已存在的业务 so 追加的 JNI 注册段（自带前缀化辅助函数，避免与文件内符号撞名）。"""
    assert ret == 's', '已存在业务 so 的假方法统一返回 String'
    salt = salt_of(mod)
    fqn = LEVEL_META[level][1]
    fn = 'j_' + method.replace('native', 'n')
    lines = []
    lines.append('')
    lines.append('/* ==================== JNI 绑定（RegisterNatives 动态注册） ==================== */')
    lines.append('#include <jni.h>')
    lines.append('#include <cstdio>')
    lines.append('#include <string>')
    lines.append('#include <cstdint>')
    lines.append('')
    lines.append('__attribute__((unused)) static std::string %s_j2s(JNIEnv* env, jstring s) {' % mod)
    lines.append('    if (s == nullptr) return std::string();')
    lines.append('    const char* c = env->GetStringUTFChars(s, nullptr);')
    lines.append('    std::string out = (c != nullptr) ? std::string(c) : std::string();')
    lines.append('    if (c != nullptr) env->ReleaseStringUTFChars(s, c);')
    lines.append('    return out;')
    lines.append('}')
    lines.append('')
    lines.append('__attribute__((unused)) static std::string %s_mix(const std::string& in, uint32_t salt, int words) {' % mod)
    lines.append('    uint32_t a = 0x811C9DC5u ^ salt;')
    lines.append('    uint32_t b = a ^ 0x9E3779B9u;')
    lines.append('    std::string out;')
    lines.append('    char buf[16];')
    lines.append('    for (int i = 0; i < words; ++i) {')
    lines.append('        b = (b << 5 | b >> 27) ^ (a + (uint32_t)(i * 0x27D4EB2Du));')
    lines.append('        a = (a << 13 | a >> 19) + (b ^ 0x165667B1u);')
    lines.append('        snprintf(buf, sizeof(buf), "%08x", b);')
    lines.append('        out += buf;')
    lines.append('    }')
    lines.append('    return out;')
    lines.append('}')
    lines.append('')
    lines.append('static jstring %s(JNIEnv* env, jobject%s) {' % (fn, c_params(params)))
    lines.append('    std::string in;')
    lines.append(build_body_lines(mod, params))
    lines.append('    return env->NewStringUTF(%s_mix(in, %uu, %d).c_str());' % (mod, salt, words_of(mod)))
    lines.append('}')
    lines.append('')
    lines.append('static const JNINativeMethod gMethods_%s[] = {' % mod)
    lines.append('    {"%s", "%s", (void*)%s},' % (method, descriptor(params, ret), fn))
    lines.append('};')
    lines.append('')
    lines.append(REG_CALL.format(cls='gMethods_%s' % mod, mod=mod, fqn=fqn))
    return '\n'.join(lines)


REG_CALL = """static void register_{mod}_methods(JavaVM* vm) {{
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return;
    jclass cls = env->FindClass("{fqn}");
    if (cls != nullptr) {{
        if (env->RegisterNatives(cls, {cls}, 1) != JNI_OK && env->ExceptionCheck())
            env->ExceptionClear();
    }} else if (env->ExceptionCheck()) {{
        env->ExceptionClear();
    }}
}}"""


def build_body_lines(ns, params):
    lines = []
    if params:
        for i, p in enumerate(params):
            if p == 's':
                lines.append('    in += %s_j2s(env, a%d);' % (ns, i))
            else:
                lines.append('    in += std::to_string((long long)a%d);' % i)
    else:
        lines.append('    in = "<probe>";')
    return '\n'.join(lines)


# ──────────────────────────── 各步骤 ────────────────────────────

def step1_rename_sources():
    renamed = []
    for old, new in RENAMES:
        old_path = os.path.join(JNI, old + '.cpp')
        new_path = os.path.join(JNI, new + '.cpp')
        if os.path.isfile(old_path):
            os.rename(old_path, new_path)
            renamed.append((old, new))
    tokens = sorted(RENAMES, key=lambda t: -len(t[0]))
    changed = 0
    for name in os.listdir(JNI):
        if not name.endswith(('.cpp', '.c')):
            continue
        p = os.path.join(JNI, name)
        text = open(p, encoding='utf-8').read()
        orig = text
        for old, new in tokens:
            text = text.replace(old, new)
        if text != orig:
            open(p, 'w', encoding='utf-8').write(text)
            changed += 1
    return renamed, changed


def step1b_rename_java_tokens():
    tokens = sorted(RENAMES, key=lambda t: -len(t[0]))
    changed = []
    for root, _dirs, files in os.walk(SRC):
        for name in files:
            if not name.endswith('.java'):
                continue
            p = os.path.join(root, name)
            text = open(p, encoding='utf-8').read()
            orig = text
            for old, new in tokens:
                text = text.replace(old, new)
            if text != orig:
                open(p, 'w', encoding='utf-8').write(text)
                changed.append(name)
    return changed


def step2_gen_decoys():
    made = []
    for level, mod, method, ret, params in DECOYS:
        if mod in EXISTING_DECOYS:
            continue
        open(os.path.join(JNI, mod + '.cpp'), 'w', encoding='utf-8').write(
            gen_decoy_source(level, mod, method, ret, params))
        made.append(mod)
    return made


def step2b_patch_existing_decoys():
    done = []
    for level, mod, method, ret, params in DECOYS:
        if mod not in EXISTING_DECOYS:
            continue
        p = os.path.join(JNI, mod + '.cpp')
        text = open(p, encoding='utf-8').read()
        if 'gMethods_%s' % mod in text:
            print('   %s 已打过补丁，跳过' % mod)
            continue
        snippet = existing_decoy_snippet(level, mod, method, ret, params)
        if 'jint JNI_OnLoad(JavaVM* vm, void*) {' in text:
            # 已有 JNI_OnLoad：片段必须插到它**之前**（片段里定义了 register_xxx_methods），
            # 同时修正 extern "C"（原先缺 C 链接 → 名字修饰 → 加载器 dlsym 找不到，从未被调用）
            idx = text.index('jint JNI_OnLoad(JavaVM* vm, void*) {')
            text = text[:idx] + snippet + '\n\n' + text[idx:]
            text = text.replace('jint JNI_OnLoad(JavaVM* vm, void*) {',
                                'extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {', 1)
            assert 'extern "C" JNIEXPORT jint JNICALL JNI_OnLoad' in text, '%s extern C 修正失败' % mod
            text = text.replace('    return JNI_VERSION_1_6;\n}',
                                '    register_%s_methods(vm);\n    return JNI_VERSION_1_6;\n}' % mod, 1)
            assert 'register_%s_methods(vm);' % mod in text, '%s 注册调用注入失败' % mod
        else:
            # 无 JNI_OnLoad：整段追加（含自带 JNI_OnLoad）
            snippet += '\n\nextern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {\n'
            snippet += '    register_%s_methods(vm);\n    return JNI_VERSION_1_6;\n}\n' % mod
            text = text.rstrip() + '\n' + snippet
        open(p, 'w', encoding='utf-8').write(text)
        done.append(mod)
    return done


def build_android_mk_block():
    per_level = {}
    for level, mod, method, ret, params in DECOYS:
        per_level.setdefault(level, []).append(mod)
    lines = []
    for level in (48, 49, 50, 51, 52, 53):
        lines.append('# L{0} —— 10 个 so（1 真 + 9 干扰，名字不体现关卡号）'.format(level))
        for m in sorted(per_level[level]) + REAL_SO[level]:
            lines.append('include $(CLEAR_VARS)')
            lines.append('LOCAL_MODULE := %s' % m)
            lines.append('LOCAL_SRC_FILES := %s.cpp' % m)
            if m in MODULE_FLAGS:
                lines.append(MODULE_FLAGS[m])
            lines.append('include $(BUILD_SHARED_LIBRARY)')
            lines.append('')
    return '\n'.join(lines)


def step3_patch_android_mk():
    path = os.path.join(JNI, 'Android.mk')
    text = open(path, encoding='utf-8').read()
    block = build_android_mk_block()
    mods = re.findall(r'LOCAL_MODULE := (\S+)', block)
    assert len(mods) == 60, 'L48-L53 段模块数应为 60，实际 %d' % len(mods)
    assert len(set(mods)) == 60, 'L48-L53 段模块名有重复'
    if '# L48 —— 10 个 so' in text:
        print('   Android.mk 已打过补丁，跳过')
        return mods
    start = text.index('# L48\ninclude $(CLEAR_VARS)\nLOCAL_MODULE := native48')
    end = text.index('# KL41 须弥界 浅滩拾贝')
    new_text = text[:start] + block + '\n' + text[end:]
    assert 'native4' not in new_text and 'native5' not in new_text, 'Android.mk 仍残留旧模块名'
    open(path, 'w', encoding='utf-8').write(new_text)
    return mods


def step4_patch_loaders():
    per_level = {}
    for level, mod, method, ret, params in DECOYS:
        per_level.setdefault(level, []).append(mod)

    def so_list_for(levels):
        out = []
        for lv in levels:
            out.extend(sorted(per_level[lv]))
            out.extend(REAL_SO[lv])
        assert len(out) == 10 * len(levels), '每组 so 数应为 10×关卡数'
        return out

    loads = {cls: so_list_for(levels) for cls, levels in LOAD_GROUPS.items()}

    # 哨兵必须选「新增的干扰 so」——改名后的真身名在 Java 里本来就已存在（loadLibrary 已被 token 替换过）
    renamed_new = {new for _old, new in RENAMES}

    def sentinel_for(levels):
        for m in sorted(per_level[levels[0]]):
            if m not in renamed_new:
                return 'System.loadLibrary("%s");' % m
        raise AssertionError('找不到可用哨兵')

    def block(names):
        body = '\n'.join('        System.loadLibrary("%s");' % n for n in names)
        return '    static {\n' + body + '\n    }'

    def patch(path, sentinel, names, anchor=None):
        t = open(path, encoding='utf-8').read()
        if sentinel in t:
            print('   %s 已打过补丁，跳过' % os.path.basename(path))
            return
        if anchor is None:
            t2 = re.sub(r'    static \{.*?\n    \}', block(names), t, count=1, flags=re.S)
            assert t2 != t, '%s 装载块未匹配' % path
        else:
            assert anchor in t, '%s 锚点未找到（Java token 替换是否已执行？）' % path
            idx = t.index(anchor)
            endm = t.index('    }\n', idx)
            t2 = t[:idx] + block(names) + '\n' + t[endm + len('    }\n'):]
        open(path, 'w', encoding='utf-8').write(t2)

    patch(os.path.join(SRC, 'AppInit.java'), sentinel_for(LOAD_GROUPS['AppInit']), loads['AppInit'])
    patch(os.path.join(SRC, 'WarmUp.java'), sentinel_for(LOAD_GROUPS['WarmUp']), loads['WarmUp'])
    patch(os.path.join(SRC, 'MainActivity.java'), sentinel_for(LOAD_GROUPS['MainActivity']),
          loads['MainActivity'], anchor='    static {\n        System.loadLibrary("crane");\n')
    return loads


def step5_patch_bridges():
    per_level = {}
    for level, mod, method, ret, params in DECOYS:
        per_level.setdefault(level, []).append((mod, method, ret, params))
    java_type = {'s': 'String', 'i': 'int', 'l': 'long'}
    summary = {}
    for level, items in sorted(per_level.items()):
        clsname = LEVEL_META[level][0]
        p = os.path.join(SRC, clsname + '.java')
        t = open(p, encoding='utf-8').read()
        anchor = '    private %s() {}' % clsname
        assert anchor in t, '%s 锚点未找到' % clsname
        probe = items[0][1]           # 该关第一个干扰方法名，作为"已打过补丁"的探针
        if probe in t:
            print('   %s 已打过补丁，跳过' % clsname)
            continue
        decls = []
        for mod, method, ret, params in items:
            args = ', '.join('%s a%d' % (java_type[q], i) for i, q in enumerate(params))
            decls.append('    public static native %s %s(%s);  // %s' % (java_type[ret], method, args, mod))
        t2 = t.replace(anchor, '\n'.join(decls) + '\n\n' + anchor, 1)
        open(p, 'w', encoding='utf-8').write(t2)
        summary[clsname] = len(items)
    return summary


def main():
    print('=== 1) 重命名 12 个 so 源文件 ===')
    renamed, changed = step1_rename_sources()
    for old, new in renamed:
        print('   %-10s -> %s.cpp' % (old, new))
    print('   同步自引用源文件数:', changed)

    print('=== 1b) 同步 app/src 下 Java 里的旧 so 名 ===')
    jc = step1b_rename_java_tokens()
    print('   改动 Java 文件数:', len(jc))

    print('=== 2) 生成 48 个干扰 so ===')
    made = step2_gen_decoys()
    print('   新生成 %d 个' % len(made))

    print('=== 2b) 给 3 个已存在业务 so 补挂 JNI 注册 ===')
    done = step2b_patch_existing_decoys()
    print('   补挂:', ', '.join(done))

    print('=== 3) 改写 Android.mk ===')
    mods = step3_patch_android_mk()
    print('   L48-L53 段模块数:', len(mods))

    print('=== 4) 改写三个装载点 ===')
    loads = step4_patch_loaders()
    for cls, names in loads.items():
        print('   %-14s %d 个' % (cls, len(names)))

    print('=== 5) 扩展 6 个 JNI 桥类 ===')
    for cls, n in step5_patch_bridges().items():
        print('   %-6s +%d 个假 native 声明' % (cls, n))

    print()
    print('完成。下一步：文档同步 + g++ 语法校验 + 清理 app/obj 与陈旧 so。')


if __name__ == '__main__':
    main()
