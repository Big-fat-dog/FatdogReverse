# FatdogReverse 第一季 · 完整题解（先自己练！）

> 建议每关至少卡 10 分钟再看对应小节。闯关的意义是练出"先搜什么、再看什么、最后用什么工具"的肌肉记忆，不是抄答案。
>
> 关卡 1-6 是纯静态分析（jadx 搜索）；关卡 7-9 是 smali 修改挑战（apktool + 重打包）；关卡 10-14 是 Frida 实战；关卡 15-25 是网络关（签名/加密取数 + TLS 抓包对抗 + native 校验），每关同样给**静态 Python 复刻**和 **Frida 动态**两条路。小白建议先把静态走通，再玩 Frida。

---

## 关卡 1：明文藏宝

**考点**：字符串常量在 dex 里永远是明文——这是整个逆向的地基。

**解法**：
1. jadx 打开 `FatdogReverse.apk`（GUI 版直接双击，或命令行 `jadx -d out FatdogReverse.apk`）。
2. 菜单/快捷键全文搜索 `FLAG_18`。
3. 命中 `TokenVaultActivity.java`，flag 就写死在 `final String flag` 里。

**答案**：`FLAG_18_L1{plain_text_in_dex}`

---

## 关卡 2：Base64 马甲

**考点**：Base64 是编码不是加密，识别特征就是"以 = 结尾的长串"。

**解法**：
1. jadx 里 `NoteKeeperActivity` 有个 `encoded` 变量，串以 `=` 结尾 → 先想到 Base64。
2. Python 解码：

```python
import base64
s = 'RkxBR18xOF9MMntiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259'
print(base64.b64decode(s).decode())   # FLAG_18_L2{base64_is_not_encryption}
```

**答案**：`FLAG_18_L2{base64_is_not_encryption}`

---

## 关卡 3：拼图游戏

**考点**：字符串被拆散 + 异或运算混淆。异或（XOR）的逆运算就是它自己：`a ^ b = c` 则 `c ^ b = a`。

**解法**：
1. jadx 里 `PuzzleBoxActivity` 的 `buildFlag()` 返回一堆 `(char) ('y' ^ 1)` 表达式。
2. 逐个计算（ASCII：`'y'=0x79, 'l'=0x6C, ...`）：

```python
# 对照源码里的表达式手工还原
chars = ['y'^1, 'l'^3, 's'^1, 'q'^1, 'v'^3, 'x'^2, 'x'^2, 'm'^1, 'g'^2]
# 在 Python 里直接：
print(''.join(chr(c) for c in chars))          # xorpuzzle
print('FLAG_18_L3{' + 'xor_puzzle' + '}')
```

3. 拼起来 `xor_puzzle`。

**答案**：`FLAG_18_L3{xor_puzzle}`

---

## 关卡 4：MD5 验门

**考点**：哈希是单向的，但弱口令可以查表/爆破；MD5 的 32 位十六进制串是特征。

**解法**：
1. jadx 里 `GateKeeperActivity` 有 `e10adc3949ba59abbe56e057f20f883e`（32 位 hex = MD5 特征）。
2. 在线查表（cmd5.com、somnium 等）→ 命中 `123456`。
3. 查不到就爆破（口令是纯数字时秒出）：

```python
import hashlib, itertools
target = 'e10adc3949ba59abbe56e057f20f883e'
for n in range(1, 7):
    for tup in itertools.product('0123456789', repeat=n):
        s = ''.join(tup)
        if hashlib.md5(s.encode()).hexdigest() == target:
            print('password =', s)     # 123456
            raise SystemExit
```

4. 输入 `123456`，Toast 显示 flag。

**答案**：`FLAG_18_L4{md5_123456}`

---

## 关卡 5：资源藏宝

**考点**：APK 本质是 zip；便宜的信息常躺在最浅的地方（assets/）。

**解法**：
1. `FatdogReverse.apk` 复制一份改后缀为 `.zip`，解压。
2. 打开 `assets/config.json`，`feature.treasure_note` 字段就是 flag。
3. （jadx 的"资源"面板也能直接看到，不用解压。）

**答案**：`FLAG_18_L5{config_json_assets}`

---

## 关卡 6：隐藏入口

**考点**：AndroidManifest 是 App 的"户口本"；`exported="true"` 的组件可被外部拉起。

**解法**：
1. jadx 打开 `AndroidManifest.xml`，看所有 Activity：`.RewardActivity` 没有 `MAIN/LAUNCHER` 意图、大厅也没有按钮指向它，但它 `exported="true"`。
2. adb 直接拉起：

```
adb shell am start -n com.fatdog.reverse/.RewardActivity
```

3. 页面直接显示 flag。

**答案**：`FLAG_18_L6{exported_activity}`

---

## 关卡 7：VIP 检测（smali）—— 去掉 isVip 检测

**考点**：smali 的寄存器常量（`const/4`）与条件跳转（`if-eqz`/`if-nez`）；apktool 解包/回编译/重签名。

**解法**：
1. 解包：

```
apktool d FatdogReverse.apk -o out
# VipSalonActivity 在 classes.dex → out/smali/com/fatdog/reverse/
```

2. 打开 `VipSalonActivity.smali`，`isVip()Z` 就三行：

```smali
.method isVip()Z
    .registers 2
    const/4 v0, 0x0      # ← 恒返回 false，这就是"不是 VIP"
    return v0
.end method
```

3. 改成 `const/4 v0, 0x1` 保存。
   （也可以不改 isVip，去 `VipSalonActivity$1.smali` 把按钮回调里的 `if-eqz p1, :cond_15` 反转为 `if-nez`，效果一样。）
4. 回编译、对齐、重签名、安装（命令见 README"通用流程"）：

```
apktool b out -o rebuilt.apk
zipalign -f 4 rebuilt.apk aligned.apk
apksigner sign --ks build/debug.keystore --ks-key-alias androiddebugkey \
        --ks-pass pass:android --key-pass pass:android --out patched.apk aligned.apk
adb install -r patched.apk
```

5. 打开点"查看会员内容" → 出 flag。

**答案**：`FLAG_18_L7{smali_vip_bypass}`

---

## 关卡 8：激活码（smali）—— 还原 fill-array-data 或改 checkKey

**考点**：smali 里字节数组的形态 `fill-array-data` + `.array-data`；方法体重写。

**解法**（两条路任选）：

**路线 A：读 smali 还原激活码。**
1. 解包后打开 `ActivationRoomActivity.smali`，`buildKey()[B` 里有一块密文：

```smali
:array_18
.array-data 1
    0x6ct  0x6bt  0x7et  0x66t  0x6bt  0x68t
    0x7t   0x18t  0x1at  0x18t  0x1ct
.end array-data
```

2. 这段字节在代码里被 `xor-int/lit8 v4, v4, 0x2a`（异或 0x2A）还原。Python 一键还原：

```python
enc = [0x6c, 0x6b, 0x7e, 0x66, 0x6b, 0x68, 0x07, 0x18, 0x1a, 0x18, 0x1c]
print(''.join(chr(b ^ 0x2A) for b in enc))     # FATLAB-2026
```

3. 输入 `FATLAB-2026` → 激活成功。

**路线 B：把 checkKey 改成恒真。** 把 `checkKey(Ljava/lang/String;)Z` 的方法体整体替换为：

```smali
.method checkKey(Ljava/lang/String;)Z
    .registers 1
    const/4 v0, 0x1
    return v0
.end method
```

回编译重签名安装后，输入随便什么都过。

**答案**：`FLAG_18_L8{smali_activation_key}`

---

## 关卡 9：多重资格（smali）—— 两个检查 + 诱饵

**考点**：smali 的短路与逻辑（`&&`）；**别把诱饵当答案**。

**解法**：
1. 打开 `ProWorkshopActivity.smali`，`checkStatus()Z` 是短路与：

```smali
.method checkStatus()Z
    invoke-direct {p0}, ...->isVip()Z
    move-result v0
    if-eqz v0, :cond_e        # isVip 假 → 直接失败
    invoke-direct {p0}, ...->isActivated()Z
    move-result v0
    if-eqz v0, :cond_e        # isActivated 假 → 失败
    const/4 v0, 0x1
    return v0
    :cond_e
    const/4 v0, 0x0
    return v0
.end method
```

2. **陷阱**：只改 `isVip()` 一个，`checkStatus` 仍返回 false，会走进 else 分支弹出 `FLAG_18_L9{single_gate_not_enough}`——它也在 smali 里，以 `FLAG_18_L9{...}` 开头，但**不是通关 flag**，是诱饵。
3. 正解二选一：
   - 把 `checkStatus()` 整个方法体改成 `const/4 v0, 0x1` + `return v0`；
   - 或把 `isVip()Z` 和 `isActivated()Z` 都改成 `const/4 v0, 0x1` + `return v0`。
4. 重打包重签名安装，点"进入工坊"。

**答案**：`FLAG_18_L9{multi_gate_cleared}`

> 提示：`lib/arm64-v8a/libnative.so` 里的 `decoy_from_native_layer` 也是结构装饰/诱饵，不是 flag。

---

## 关卡 10：SHA-256 验门（Frida 第 1 关）

**考点**：SHA-256 是 64 位 hex；Frida Hook `java.security.MessageDigest`；篡改 `verify()` 返回值。

**静态解法**：
1. jadx 看 `HashCheckActivity.verify()`：

```java
boolean verify(String password) {
    return sha256Hex(password).equals("db77ca6bb991f807190b0c8cb00c09b74094f089a2efb2a0e629d00540973846");
}
```

2. 口令是教程 20 主角的名字（全小写），Python 验证：

```python
import hashlib
target = 'db77ca6bb991f807190b0c8cb00c09b74094f089a2efb2a0e629d00540973846'
for w in ('frida', 'frida2026', 'frida888'):
    if hashlib.sha256(w.encode()).hexdigest() == target:
        print('password =', w)     # frida
```

**Frida 解法**：
1. 观察法——看 verify 的入参和 digest 的输入/输出：

```javascript
// hook_l10.js
Java.perform(function () {
    var HC = Java.use('com.fatdog.reverse.HashCheckActivity');
    HC.verify.implementation = function (password) {
        console.log('[verify] 入参 password =', password);
        var ret = this.verify(password);
        console.log('[verify] 返回值 =', ret);
        return ret;
    };
});
// 运行：frida -U -n 应用名 -l hook_l10.js  然后随便输几个口令观察
```

2. 篡改法——直接让 verify 永远返回 true，输入任意字符都出 flag：

```javascript
// hook_l10_force.js
Java.perform(function () {
    Java.use('com.fatdog.reverse.HashCheckActivity')
        .verify.implementation = function (password) { return true; };
});
```

**答案**：`FLAG_18_L10{sha256_gate_cleared}`

---

## 关卡 11：HMAC 验签（Frida 第 2 关）

**考点**：HMAC = 带密钥的哈希；Frida Hook `javax.crypto.Mac.doFinal`。

**静态解法**：
1. jadx 看 `MsgAuthActivity`：密钥 `fatdemo_hmac_key`，内置值是 HMAC-SHA256 结果。
2. Python 复刻：

```python
import hmac, hashlib
key = b'fatdemo_hmac_key'
target = '042dab800cab0a8df5cce658e0bc05c68b7e8bcd3e897e887b60c1807c31b77c'
for w in ('fatlab', 'fatlab2026'):
    if hmac.new(key, w.encode(), hashlib.sha256).hexdigest() == target:
        print('password =', w)     # fatlab
```

**Frida 解法**：Hook Mac，看它算的是什么、算出什么（和静态对着看）：

```javascript
// hook_l11.js
Java.perform(function () {
    function b2h(b) { var s=''; for (var i=0;i<b.length;i++){var x=b[i]&0xff; s+=('0'+x.toString(16)).slice(-2);} return s; }
    var Mac = Java.use('javax.crypto.Mac');
    Mac.doFinal.overload('[B').implementation = function (data) {
        console.log('[mac] 输入:', b2h(data), '->', Java.use('java.lang.String').$new(data));
        var r = this.doFinal(data);
        console.log('[mac] 输出:', b2h(r));
        return r;
    };
    Java.use('com.fatdog.reverse.MsgAuthActivity')
        .verify.implementation = function (p) { return true; };   // 或者直接篡改
});
```

**答案**：`FLAG_18_L11{hmac_sign_passed}`

---

## 关卡 12：AES 密码库（Frida 第 3 关）

**考点**：AES-CBC 的密钥/IV/密文三件套；**内容开始分散到工具类**（`SBox`），且开始出现**诱饵类**（`Md5Wrap`、`MiscCrypt` 无人调用）。

**静态解法**：
1. jadx 看 `b1Activity.verify()`，它只调用 `SBox.decryptVault()`；真正的东西在 `SBox`：

```java
static final byte[] KEY = "FATDEMO_KEY_12AB".getBytes();
static final byte[] IV  = "0001020304050607".getBytes();
static final String VAULT = "Grg3J5v8Lh0r9KyE0Py0zw==";
// 用 Cipher.getInstance("AES/CBC/PKCS5Padding") 解密 VAULT
```

2. Python 解密（需要 `pip install pycryptodome`）：

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = b'FATDEMO_KEY_12AB'
iv  = b'0001020304050607'
data = base64.b64decode('Grg3J5v8Lh0r9KyE0Py0zw==')
plain = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data), 16)
print(plain.decode())    # vault_ok_123
```

3. 输入 `vault_ok_123` → 出 flag。

**Frida 解法**：Hook `Cipher.doFinal`，点一次验证就能看到"密文 → 明文"：

```javascript
// hook_l12.js
Java.perform(function () {
    function b2h(b) { var s=''; for (var i=0;i<b.length;i++){var x=b[i]&0xff; s+=('0'+x.toString(16)).slice(-2);} return s; }
    var C = Java.use('javax.crypto.Cipher');
    C.doFinal.overload('[B').implementation = function (input) {
        var r = this.doFinal(input);
        console.log('[cipher] 输入:', b2h(input), '-> 输出:', b2h(r), '=', Java.use('java.lang.String').$new(r));
        return r;
    };
    Java.use('com.fatdog.reverse.b1Activity')
        .verify.implementation = function (p) { return true; };
});
```

**答案**：`FLAG_18_L12{aes_vault_unlocked}`

---

## 关卡 13：双重校验（Frida 第 4 关）

**考点**：**双参数 + 双算法**；一关的内容横跨多个类（`SignUtil` + `KBox`）；用 jadx"Find Usage"排除诱饵（`HashFactory` 无人调用）。

**静态解法**：
1. jadx 看 `k4Activity.verify(account, token)`：`SignUtil.checkAccount(account) && KBox.checkToken(token)`。
2. 账号：`SignUtil` 里 `ACCOUNT_HASH` 是 MD5，对应 `neon_user`：

```python
import hashlib
print(hashlib.md5(b'neon_user').hexdigest())
# c2fb08b69f270e9aae6e76438ec724a3 ← 和代码里一致，账号就是 neon_user
```

3. 令牌：`KBox` 里 `TOKEN_KEY = "NEON_TOKEN_KEY16"`、`TOKEN_ENC = "WG2qYEkmVR5yFwooXN1VSw=="`，是 AES-ECB 密文：

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

data = base64.b64decode('WG2qYEkmVR5yFwooXN1VSw==')
plain = unpad(AES.new(b'NEON_TOKEN_KEY16', AES.MODE_ECB).decrypt(data), 16)
print(plain.decode())    # neon_token_ok
```

4. 输入账号 `neon_user`、令牌 `neon_token_ok` → 出 flag。

**Frida 解法**：一个脚本同时 Hook MessageDigest 和 Cipher（注意这关会触发两次加密原语调用）：

```javascript
// hook_l13.js
Java.perform(function () {
    function b2h(b) { var s=''; for (var i=0;i<b.length;i++){var x=b[i]&0xff; s+=('0'+x.toString(16)).slice(-2);} return s; }
    var MD = Java.use('java.security.MessageDigest');
    MD.digest.overload('[B').implementation = function (d) { console.log('[md5] 输入:', b2h(d)); return this.digest(d); };
    var C = Java.use('javax.crypto.Cipher');
    C.doFinal.overload('[B').implementation = function (d) {
        var r = this.doFinal(d);
        console.log('[aes] 输出:', b2h(r), '=', Java.use('java.lang.String').$new(r));
        return r;
    };
    Java.use('com.fatdog.reverse.k4Activity')
        .verify.implementation = function (a, t) { console.log('account =', a, 'token =', t); return true; };
});
```

**答案**：`FLAG_18_L13{dual_param_dual_alg}`

---

## 关卡 14：三层链路（Frida 第 5 关，最难）

**考点**：**一条输入链过三次变换**（base64 + AES×2 + XOR）；两把密钥分散在两个工具类；**大量诱饵类**（`AesKit`、`Md5Tools`、`KeyFactory`——尤其 KeyFactory 里有一把假密钥，别上当）；正确使用 jadx 交叉引用定位真实链路。

**静态解法**：
1. jadx 看 `z9Activity.verify(license, deviceId)`：

```java
byte[] s1 = XBox.decryptA(license);          // 第 1 层：base64 + AES-ECB(密钥A在XBox)
String plain = Mux.finish(s1);               // 第 2、3 层：AES-ECB(密钥B在Mux) + 逐字节异或 0x5A
return "GRANTED_2026_OK!".equals(plain)
        && md5Hex(deviceId).equals("a94f8d335f87849687b77fb244a1d6f4");
```

2. 提取三样东西：
   - `XBox.KEY_A = "PIVOT_KEY_A_0001"`
   - `Mux.KEY_B = "PIVOT_KEY_B_0001"`，`Mux.XOR_KEY = 0x5A`
   - 目标明文 `"GRANTED_2026_OK!"`（16 字节，正好一个 AES 块，所以 XBox/Mux 都用 `AES/ECB/NoPadding`）

3. Python **反向构造 license**（把链路反过来：明文 → 异或 → AES 加密密钥B → AES 加密密钥A → base64）：

```python
import base64
from Crypto.Cipher import AES

target = b'GRANTED_2026_OK!'                 # 16 字节
xored  = bytes(b ^ 0x5A for b in target)     # 反向异或（异或的逆就是自己）
encB   = AES.new(b'PIVOT_KEY_B_0001', AES.MODE_ECB).encrypt(xored)
license = base64.b64encode(AES.new(b'PIVOT_KEY_A_0001', AES.MODE_ECB).encrypt(encB)).decode()
print(license)                                # /ypiwyDoIxHtJkdhGceyRw==
```

4. deviceId：`md5Hex(deviceId) == a94f8d335f87849687b77fb244a1d6f4` → `pivot_device`（Python `hashlib.md5(b'pivot_device').hexdigest()` 验证）。
5. 输入 license 和 deviceId → 出 flag。

**Frida 解法**：Hook `Cipher.doFinal`，点一次验证会**连触发两次**（先密钥A再密钥B），正好让你看清整条链；`MessageDigest` 管 deviceId：

```javascript
// hook_l14.js
Java.perform(function () {
    function b2h(b) { var s=''; for (var i=0;i<b.length;i++){var x=b[i]&0xff; s+=('0'+x.toString(16)).slice(-2);} return s; }
    var C = Java.use('javax.crypto.Cipher');
    C.doFinal.overload('[B').implementation = function (d) {
        var r = this.doFinal(d);
        console.log('[cipher] 输入:', b2h(d), '-> 输出:', b2h(r));
        return r;
    };
    var MD = Java.use('java.security.MessageDigest');
    MD.digest.overload('[B').implementation = function (d) { console.log('[md5] 输入:', b2h(d)); return this.digest(d); };
    Java.use('com.fatdog.reverse.z9Activity')
        .verify.implementation = function (l, d) { console.log('license =', l, 'device =', d); return true; };
});
```

**答案**：`FLAG_18_L14{triple_layer_chain}`

---

## 关卡 15：千数求和（网络关，数据只能发包拿）

**考点**：请求参数里的签名（HMAC-SHA256）；**数据只在服务端、APK 里没有**——这是 Frida/签名逆向的完整闭环：先用 Frida 观察 App 发包瞬间怎么算签名，再复刻签名取数。

**环境**：先启动本地模拟服务端：

```
python server.py           # 监听 127.0.0.1:8787
```

App 端地址由 `NetHost` 自动切换：模拟器走 `http://10.0.2.2:8787`（宿主机回环），真机走 `http://127.0.0.1:8787`（需 `adb reverse tcp:8787 tcp:8787`），无需改 config.json。

**玩法**：1000 个数字 = 100 页 × 每页 10 个。每页请求 `GET /api/page?page=N&ts=T&sign=S`，服务端验签通过才返回该页数字。取满 100 页求和（= 49580），把加和填进 App 提交，App 用内置 SHA-256 校验后给出 flag。

**静态解法**（读代码 → 复刻签名 → 发包取数）：
1. jadx 看 `s5Activity` → 它调 `Sg.fetchPage(base, page)`。`Sg` 里签名是：

```java
static String sign(int page, long ts) {
    return hmacSha256Hex(buildKey(), "page=" + page + "&ts=" + ts);
}
static String buildKey() { return Kx.decodePartA() + decodePartB(); }
```

2. 完整密钥**不在代码里以明文出现**，拆成了两段异或字节数组（`^0x3C`）：
   - `Kx.PA = {90,93,72,88,89,81,83,99}` → `fatdemo_`
   - `Sg.PB = {76,93,91,89,99,87,89,69,99,14,12,14,10}` → `page_key_2026`
   - 拼起来 `fatdemo_page_key_2026`。

3. Python 复刻（纯标准库，无需装包）：

```python
import hashlib, hmac, json, time, urllib.request

def decode(bs):                       # 把异或字节数组还原成字符串
    return bytes(b ^ 0x3C for b in bs).decode()

key = decode([90,93,72,88,89,81,83,99]) + decode([76,93,91,89,99,87,89,69,99,14,12,14,10])
print('key =', key)                    # fatdemo_page_key_2026

def fetch_page(page):
    ts = int(time.time())
    msg = 'page=%s&ts=%s' % (page, ts)
    sign = hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()
    url = 'http://127.0.0.1:8787/api/page?%s&sign=%s' % (msg, sign)   # Python 跑在电脑上，直接用本机回环
    with urllib.request.urlopen(url) as r:
        return json.loads(r.read())

total = 0
for p in range(1, 101):
    total += sum(fetch_page(p)['nums'])
print('sum =', total)                   # 49580
```

4. 把 `49580` 填进 App"提交答案" → flag。（`TokenGen`/`DigestBox` 是没人调用的诱饵；`config.json` 的 `api_base_url` 默认 `"AUTO"`，不是秘密。）

**Frida 解法**：让 App 自己在"请求该页"里发包，趁机 Hook 签名/密钥/网络层：

```javascript
// hook_l15.js
Java.perform(function () {
    // ① 看签名输入串与输出（页面号、时间戳、sign）
    Java.use('com.fatdog.reverse.Sg').sign.implementation = function (page, ts) {
        var ret = this.sign(page, ts);
        console.log('[sign] page=' + page + ' ts=' + ts + ' -> ' + ret);
        return ret;
    };
    // ② 看拼出来的完整密钥
    Java.use('com.fatdog.reverse.Sg').buildKey.implementation = function () {
        var k = this.buildKey();
        console.log('[buildKey] key =', k);
        return k;
    };
    // ③ 看最终请求 URL
    var U = Java.use('java.net.URL');
    U.$init.overload('java.lang.String').implementation = function (s) {
        if (s.indexOf('/api/page') >= 0) console.log('[URL]', s);
        this.$init(s);
    };
});
// 跑脚本后，在 App 里点"请求该页"，控制台会打出 key 和带 sign 的完整 URL
```

看到 key = `fatdemo_page_key_2026` 后，回到上面的 Python 复刻脚本取数求和即可。

**答案**：加和 `49580`；flag `FLAG_18_L15{thousand_number_sum}`

---

## 关卡 16：流密码暗河（RC4 + MD5，请求响应都加密）

**考点**：从这一关开始，请求参数**整段加密**。L15 只有签名（参数是明文），L16 把 `page=N&ts=T` 先用 RC4 加密成 hex，再对密文做 MD5 签名；响应体也用**另一把** RC4 密钥加密。抓包时 URL 里是 `payload=一堆hex`，响应是 `{"d":"一堆hex"}`——没有密钥就两眼一抹黑。

**类在哪**：大厅按钮 → `t6Activity` → `C16.fetchPage`。三把密钥的碎片一半在 `Jk`（前缀）、一半在 `C16`（后缀），都是异或字节数组；RC4 原语在 `Rc4Core`。`B64Kit`/`TokenGen`/`DigestBox` 是没人调用的诱饵。

**先读懂流程**（`C16` 的注释写得很直白）：

```text
plain   = "page=N&ts=T"
payload = hex(RC4(reqKey, plain))
sig     = md5(payload + sigSalt)
GET /api/rc4?payload=…&sig=…
响应 {"d": hex(RC4(rspKey, "page=N|nums=a,b,…"))}
```

**静态解法**：

1. **还原三把密钥**。手工算也行，但更聪明的做法是直接 Frida 打印（见下）；这里给出异或规则供核对：
   - 请求密钥：`Jk.RA`（^0x5A）→ `fatdemo_rc4_`，`C16.K1B`（^0x3C）→ `req_2026`，拼起来 `fatdemo_rc4_req_2026`
   - 响应密钥：`Jk.KA`（^0x6B）→ `fatdemo_rc4_`，`C16.K2B`（^0x51）→ `rsp_2026`，拼起来 `fatdemo_rc4_rsp_2026`
   - MD5 盐：`Jk.SA`（^0x7D）→ `fatdemo_rc4`，`C16.SB`（^0x3C）→ `_sig_salt`，拼起来 `fatdemo_rc4_sig_salt`
2. **RC4 是流密码**：加密和解密是同一个函数（明文/密文逐字节异或密钥流），所以 Python 里一把 `rc4()` 走天下。
3. 完整复刻脚本（60 页 × 每页 8 个，取回求和）：

```python
import hashlib, json, time, urllib.request

def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):                      # KSA：用密钥打乱 S 盒
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:                            # PRGA：边搅边吐密钥流
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xff])
    return bytes(out)

REQ_KEY = b'fatdemo_rc4_req_2026'
RSP_KEY = b'fatdemo_rc4_rsp_2026'
SALT    = b'fatdemo_rc4_sig_salt'

def fetch(page):
    ts = int(time.time())
    plain = ('page=%d&ts=%d' % (page, ts)).encode()
    payload = rc4(REQ_KEY, plain).hex()
    sig = hashlib.md5((payload + SALT.decode()).encode()).hexdigest()
    url = 'http://127.0.0.1:8787/api/rc4?payload=%s&sig=%s' % (payload, sig)
    with urllib.request.urlopen(url) as r:
        obj = json.loads(r.read())
    clear = rc4(RSP_KEY, bytes.fromhex(obj['d'])).decode()
    nums = [int(x) for x in clear.split('|')[1].split('=')[1].split(',')]
    return nums

total = 0
for p in range(1, 61):
    total += sum(fetch(p))
print(total)          # 24074
```

**Frida 解法**：密钥必经过 `Rc4Core.crypt`，Hook 它一次，三把密钥和明文全部自动现形（类名没被混淆，可以直接 `Java.use`）：

```javascript
Java.perform(function () {
  var R = Java.use('com.fatdog.reverse.Rc4Core');
  R.crypt.implementation = function (data, key) {
    var hex = function (b) { var s = ''; for (var i = 0; i < b.length; i++) { s += ('0' + (b[i] & 0xff).toString(16)).slice(-2); } return s; };
    var out = this.crypt(data, key);
    console.log('[RC4] key=' + hex(key) + ' in=' + hex(data) + ' out=' + hex(out));
    return out;
  };
});
// 在 App 里点“请求该页”，控制台自动打出 reqKey/rspKey 和加解密前后的数据
```

**答案**：加和 `24074`；flag `FLAG_18_L16{rc4_stream_encrypted}`

---

## 关卡 17：玄门遁甲（国密 SM4 + SM3 表单）

**考点**：POST 表单里塞了一堆字段，但服务端只认 `enc/sig/ts/dog` 四个；`enc` 是国密 SM4 密文、`sig` 是国密 SM3 摘要，其余 `client/chan/ver/dev` 全是干扰项（`dev` 每次还是随机 hex，重放时长得不一样，用来吓唬人的）。响应体也是 SM4 密文。

**类在哪**：`u7Activity` → `Fl.fetchPage`。密钥碎片一半在 `Kt`、一半在 `Fl`；`Sm4Core`/`Sm3Core` 是手写国密实现（SM4：ECB + PKCS7 填充；对应教程 12 篇国密）。诱饵 `NetPacker`。

**先读懂流程**：

```text
enc = hex(SM4("fatdemo_form_key", "page=N&ts=T"))
sig = SM3(enc + "fatdemo_sm3_salt")
dog = "fatdog"                          # 固定参数，服务端对不上就 403
POST /api/form  → page/ts/dog/enc/sig + client/chan/ver/dev(随机) 干扰
响应 {"d": hex(SM4("fatdemo_resp_key", "page=N|nums=…"))}
服务端额外校验：enc 解出来的 page/ts 必须和表单里的明文字段一致（防止抓包后改字段重放）
```

**静态解法**：

1. 还原密钥（`Kt` 前缀 + `Fl` 后缀）：
   - `fatdemo_form_` + `key` = `fatdemo_form_key`（请求密钥）
   - `fatdemo_resp_` + `key` = `fatdemo_resp_key`（响应密钥）
   - `fatdemo_sm3_` + `salt` = `fatdemo_sm3_salt`（SM3 盐）
   - `fat` + `dog` = `fatdog`
2. SM4/SM3 不想手写？**项目自带的 `server.py` 里就有纯 Python 实现**，直接 import 复用（这也是"靶场服务端在你手上"的便利）：

```python
import json, sys, time, urllib.request, urllib.parse
sys.path.insert(0, r'E:\pyteacher\FatdogReverse')
from server import sm3_hex, sm4_encrypt, sm4_decrypt   # 借用服务端的国密实现

REQ_KEY = b'fatdemo_form_key'
RSP_KEY = b'fatdemo_resp_key'
SALT    = 'fatdemo_sm3_salt'

def fetch(page):
    ts = int(time.time())
    enc = sm4_encrypt(('page=%d&ts=%d' % (page, ts)).encode(), REQ_KEY).hex()
    sig = sm3_hex((enc + SALT).encode())
    form = urllib.parse.urlencode({
        'page': page, 'ts': ts, 'dog': 'fatdog', 'enc': enc, 'sig': sig,
        'client': 'android-fatdemo', 'chan': 'ctf', 'ver': '1.7', 'dev': '00' * 8,
    }).encode()
    req = urllib.request.Request('http://127.0.0.1:8787/api/form', data=form)
    with urllib.request.urlopen(req) as r:
        obj = json.loads(r.read())
    clear = sm4_decrypt(bytes.fromhex(obj['d']), RSP_KEY).decode()
    nums = [int(x) for x in clear.split('|')[1].split('=')[1].split(',')]
    return nums

total = 0
for p in range(1, 101):
    total += sum(fetch(p))
print(total)          # 50636
```

（不想 import server.py 也可以 `pip install gmssl`，接口几乎一样。）

**Frida 解法**：这关的密钥也是静态拼装，Hook 几个 build 方法一次性打印：

```javascript
Java.perform(function () {
  var Fl = Java.use('com.fatdog.reverse.Fl');
  console.log('[L17] reqKey = ' + Fl.buildReqKey());
  console.log('[L17] rspKey = ' + Fl.buildRspKey());
  console.log('[L17] salt   = ' + Fl.buildSigSalt());
  console.log('[L17] dog    = ' + Fl.dog());
});
// attach 后点“请求该页”前先跑一次，控制台直接出四串
```

**答案**：加和 `50636`；flag `FLAG_18_L17{sm4_sm3_form}`

---

## 关卡 18：乾坤密钥（RSA 加密参数 + DES 解密响应）

**考点**：非对称 + 对称混搭。请求参数用 RSA 公钥加密（服务端私钥解密，参数抓不到明文）；响应体用 DES 加密，而 DES 密钥是**一半服务端下发、一半藏在 App**，运行时拼装——抓包只能看到一半密钥，另一半要逆向 App。

**类在哪**：`v8Activity` 进入后先调 `Rs.init`（`GET /api/dskey` 拿密钥前半段）再 `Rs.fetchPage`。RSA 模数藏在 `Pk.NX`（128 字节，异或 0x5A）；DES 后半段在 `Pk.HB`（异或 0x3C → `key!`）。诱饵 `RsaKit`。

**先读懂流程**：

```text
第一步  GET /api/dskey → {"k":"64733138"}   hex 解码 = "ds18"
DES 密钥 = "ds18" + "key!" = "ds18key!"      （8 字节，DES 标准长度）
enc = hex(RSA/ECB/PKCS1Padding(pubkey, "page=N&ts=T"))
POST /api/rsa  → page/ts/enc + client/chan/ver/dev 干扰
响应 {"d": hex(DES/ECB/PKCS5("ds18key!", "page=N|nums=…"))}
```

**静态解法**：

1. **公钥**：指数固定 `65537`；模数把 `Pk.NX` 每个数 `^ 0x5A` 后拼成 128 字节。嫌数组太长，可以直接从 `server.py` 抄 `KEY18_RSA_N`（本靶场服务端就在你硬盘上；真实世界当然没这好事，所以先把"从 NX 异或还原"的手艺练熟）。
2. **DES 密钥**：先请求 `/api/dskey` 拿 `"ds18"`，拼上从 `Pk.HB` 还原的 `"key!"`。
3. Python 复刻（需要 `pip install pycryptodome`）：

```python
import json, time, urllib.request, urllib.parse
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, DES
from Crypto.Util.Padding import unpad

N = int('adfad72ed2b45844ab2f8a41c056836c58428b3673da423d9f1f8425d1ee895e'
        'a26f71c808b38f7b8839f9c8ace28478eb2f84b415930e10bb339023d83ee7c'
        'c9e5b89bcbf97f2b15d72a712727ed34d71d23d783b34aef3bc75f9cf5e1ea'
        '2c1db0547d9b3373a75e2116c11acc6d3f17e5e7bedccb5415079743aee417c2f4d', 16)
E = 65537

def fetch(page):
    ts = int(time.time())
    msg = ('page=%d&ts=%d' % (page, ts)).encode()
    enc = PKCS1_v1_5.new(RSA.construct((N, E))).encrypt(msg).hex()
    form = urllib.parse.urlencode({
        'page': page, 'ts': ts, 'enc': enc,
        'client': 'android-fatdemo', 'chan': 'ctf', 'ver': '1.8', 'dev': '0' * 16,
    }).encode()
    req = urllib.request.Request('http://127.0.0.1:8787/api/rsa', data=form)
    with urllib.request.urlopen(req) as r:
        obj = json.loads(r.read())
    key = b'ds18' + b'key!'                    # 服务端半段 + Pk 里的半段
    clear = unpad(DES.new(key, DES.MODE_ECB).decrypt(bytes.fromhex(obj['d'])), 8).decode()
    nums = [int(x) for x in clear.split('|')[1].split('=')[1].split(',')]
    return nums

total = 0
for p in range(1, 101):
    total += sum(fetch(p))
print(total)          # 51258
```

**Frida 解法**：模数、DES 半段、加解密入参全都能直接 Hook：

```javascript
Java.perform(function () {
  function bytesToStr(b) { var s = ''; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i] & 0xff); return s; }
  var Pk = Java.use('com.fatdog.reverse.Pk');
  console.log('[L18] n       = ' + Pk.modulus().toString(16));
  console.log('[L18] desHalf = ' + bytesToStr(Pk.desHalfB()));      // key!
  var Rs = Java.use('com.fatdog.reverse.Rs');
  Rs.rsaEncHex.implementation = function (p) { var r = this.rsaEncHex(p); console.log('[L18] plain=' + p + ' enc=' + r); return r; };
  Rs.desDecryptStr.implementation = function (h) { var r = this.desDecryptStr(h); console.log('[L18] resp=' + r); return r; };
});
```

**答案**：加和 `51258`；flag `FLAG_18_L18{rsa_des_form}`

---

## 关卡 19：雾里看花（AES + HMAC，加密包被真 R8 混淆）

**考点**：这是 15-19 里最"仿真"的一关：放算法的整个 `com.fatdog.reverse.o` 包被 **R8 重命名**成 `a/b/c` 之类，且算法名、接口路径、三把密钥全是**异或加密串**——jadx 里搜 `AES`、`/api/l19` 什么都搜不到。教程 19 第 8 节"字符串加密 + 混淆"的真实组合。

**类在哪**：`v9Activity` → `o.Api.fetchPage`；加解密原语在 `o.Encrypt`；字符串/密钥在 `o.Keys`；`o.Dummy` 是诱饵（假密钥，没人调）。构建后这几个类会变成 `o.a/o.b/o.c/o.d`——**对不上号没关系**，从 `v9Activity` 的调用链顺藤摸瓜即可。

**先读懂流程**（逻辑和 L15 很像，只是换算法+藏得更深）：

```text
enc  = hex(AES/ECB/PKCS5("fatdemo_aeskey19", "page=N&ts=T"))
sign = HMAC-SHA256("fatdemo_hmac_key", enc)
POST /api/l19  → page/ts/enc/sign + client/chan/ver/dev 干扰
响应 {"d": hex(AES/ECB/PKCS5("fatdemo_rspkey19", "page=N|nums=…"))}
```

**静态解法**：

1. 别搜算法名，搜**调用链**：jadx 里从 `v9Activity` 出发，看它调了 `o` 包下哪个方法，一层层跟到"做 AES 的那个类"。
2. 三把密钥在 `Keys` 的异或数组里（^0x5A）：`Q_RK`→`fatdemo_aeskey19`、`Q_HK`→`fatdemo_hmac_key`、`Q_SK`→`fatdemo_rspkey19`；算法名/路径是 ^0x33。手工异或或 Frida 打印都行。
3. Python 复刻（`pip install pycryptodome`）：

```python
import hashlib, hmac, json, time, urllib.request, urllib.parse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

AES_KEY  = b'fatdemo_aeskey19'
HMAC_KEY = b'fatdemo_hmac_key'
RSP_KEY  = b'fatdemo_rspkey19'

def fetch(page):
    ts = int(time.time())
    enc = AES.new(AES_KEY, AES.MODE_ECB).encrypt(pad(('page=%d&ts=%d' % (page, ts)).encode(), 16)).hex()
    sign = hmac.new(HMAC_KEY, enc.encode(), hashlib.sha256).hexdigest()
    form = urllib.parse.urlencode({
        'page': page, 'ts': ts, 'enc': enc, 'sign': sign,
        'client': 'android-fatdemo', 'chan': 'ctf', 'ver': '1.9', 'dev': '0' * 16,
    }).encode()
    req = urllib.request.Request('http://127.0.0.1:8787/api/l19', data=form)
    with urllib.request.urlopen(req) as r:
        obj = json.loads(r.read())
    clear = unpad(AES.new(RSP_KEY, AES.MODE_ECB).decrypt(bytes.fromhex(obj['d'])), 16).decode()
    nums = [int(x) for x in clear.split('|')[1].split('=')[1].split(',')]
    return nums

total = 0
for p in range(1, 101):
    total += sum(fetch(p))
print(total)          # 51648
```

**Frida 解法**：类名被混淆了没关系——`javax.crypto` 的类改不了名。Hook 加密原语，所有明文都会路过这里：

```javascript
Java.perform(function () {
  function hex(b) { var s = ''; for (var i = 0; i < b.length; i++) { s += ('0' + (b[i] & 0xff).toString(16)).slice(-2); } return s; }
  function str(b) { var s = ''; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i] & 0xff); return s; }
  var C = Java.use('javax.crypto.Cipher');
  C.doFinal.overload('[B').implementation = function (d) {
    var r = this.doFinal(d);
    console.log('[cipher] in=' + hex(d) + ' out=' + hex(r));
    return r;
  };
  var M = Java.use('javax.crypto.Mac');
  M.doFinal.overload('[B').implementation = function (d) {
    var r = this.doFinal(d);
    console.log('[mac] in=' + str(d) + ' out=' + hex(r));
    return r;
  };
});
// 点“请求该页”，控制台会按顺序打出：参数明文 → enc → HMAC 输入 → 响应密文 → 响应明文
```

**答案**：加和 `51648`；flag `FLAG_18_L19{obfuscated_aes_hmac}`

---
## 关卡 20：万恶广告劫（smali，关不掉的牛皮癣广告）

**考点**：smali 里的「开关字段 + 条件跳转」与 `packed-switch` 状态机；这关的 jadx Java 反编译比 smali 还难读——广告文案全是异或 0x4D 的神秘数字、`switch(step)` 被展开成巨型判断，而 smali 一眼见底。

**玩法**：进关卡只有一个「点此领取 1 亿大礼包」→ 点了就弹连环广告：`switch(step)` 一轮 8 条（5 张广告图循环复用），× 前 5 秒不显示、显示后点击会瞬移四角 + 嘲讽 Toast、连点 3 次出现「看完关闭」，点了进下一条……**正常操作永远关不完**。把广告开关关掉才能通关。

**关键点 / 类在哪**：
- `a20Activity`（关卡页）+ `AdBox`（广告机）。**真正的开关是 `AdBox.a`**（`public static int a = 1`）。
- `PhantomAd.enabled` 是**假开关（诱饵）**：名字带 ad 但 AdBox 从不读它。
- `showAd` 的 smali（apktool 解包后 `smali/com/fatdog/reverse/AdBox.smali`）：

```smali
.field public static a:I = 0x1      # ← 唯一的真开关

.method public static showAd(Landroid/app/Activity;)V
    sget v0, Lcom/fatdog/reverse/AdBox;->a:I   # 读开关
    if-nez v0, :cond_8                         # ≠0 才弹广告
    invoke-static {p0}, …AdBox->gone(Landroid/app/Activity;)V
    return-void
    :cond_8
    sget v0, …AdBox->step:I
    …
    packed-switch v0, :pswitch_data_xx          # 8 条连环广告 switch 表（数据区可看到 8 个标签）
```

**解法 A：apktool 改 smali（正解）**
1. `apktool d FatdogReverse.apk -o out`（单 classes.dex → `out/smali/com/fatdog/reverse/`，已无 classes2/3）。
2. 改 `out/smali/com/fatdog/reverse/AdBox.smali`，二选一：
   - 把 `.field public static a:I = 0x1` 的 `0x1` 改成 `0x0`；
   - 或把 `showAd` 开头的 `if-nez v0, :cond_8` 反转为 `if-eqz`。
3. 回编译重签名重装（见 README smali 流程）：
   `apktool b out -o rebuilt.apk` → `zipalign -f 4` → `apksigner sign` → `adb install -r`。
4. 进关卡点「领取大礼包」→ 不再弹广告 → 出现「我已关掉广告」→ 点击 → 礼花 + flag。

**解法 B：Frida（双解）**
```javascript
Java.perform(function () {
    Java.use('com.fatdog.reverse.AdBox').a.value = 0;   // 直改真开关
});
```
挂上后点按钮，广告即断，点「我已关掉广告」通关。

**干扰项提醒**：广告文案全是异或 0x4D 的神秘数字（别浪费时间解文案）；`PhantomAd.enabled` 是假开关，改了没用；`step` 只是 8 条广告翻页计数，改它跳不出循环——**只有 `AdBox.a` 有效**。

**答案**：flag `FLAG_18_L20{ads_are_gone}`（无数字，改掉开关点按钮即通）

## 关卡 21：踏云寻踪（HTTPS + 自定义 TrustManager）

**考点**：服务端升级 HTTPS（自签 CA）。App 的 OkHttp 客户端装了一个**自定义 TrustManager**，只信内置的自签 CA——代理工具（mitmproxy/Fiddler/Charles）换发的证书不是这个 CA 签的，握手直接失败。这就是教程 21 的第一道闸：抓包先被信任校验挡住。

**类在哪**：`w1Activity` → `Tm.fetchPage`。CA 证书的 DER 字节藏在 `Tm.CAA`（异或 0x5A）；HMAC 密钥一半在 `Km`（`fatdemo_`）、一半在 `Tm.TB`（`ssl_hmac`）。诱饵 `CertBox`。

**先读懂流程**：

```text
sign = HMAC-SHA256("fatdemo_ssl_hmac", "page=N&ts=T")
GET https://…:8443/api/tls?page=N&ts=T&sign=…
响应 {"page":N,"nums":[…]}        ← 明文！这关的难点全在 TLS 握手，不在加解密
```

**解法 A：带 CA 复刻（最正，推荐先走这条）**。项目 `certs/ca.crt` 就是 App 内置的那张自签 CA。Python 用它当信任锚，直接复刻签名取数：

```python
import hmac, hashlib, json, ssl, time, urllib.request

KEY = b'fatdemo_ssl_hmac'
ctx = ssl.create_default_context(cafile='certs/ca.crt')   # 证书 SAN 已含 127.0.0.1/10.0.2.2/localhost

def fetch(page):
    ts = int(time.time())
    msg = 'page=%d&ts=%d' % (page, ts)
    sign = hmac.new(KEY, msg.encode(), hashlib.sha256).hexdigest()
    url = 'https://127.0.0.1:8443/api/tls?page=%d&ts=%d&sign=%s' % (page, ts, sign)
    with urllib.request.urlopen(url, context=ctx) as r:
        obj = json.loads(r.read())
    return obj['nums']

total = 0
for p in range(1, 101):
    total += sum(fetch(p))
print(total)          # 51496
```

**解法 B：带 CA 抓包**。把 `certs/ca.crt` 导入 Fiddler/mitmproxy/Charles 当中间人证书（或直接让它作为代理的 CA），App 就会信任代理签的证书——因为那"同一个 CA"本身就是它信任的锚。然后像 L15 一样抓包看 URL 和参数。

**解法 C：Frida 拆信任校验（无脑流）**。经典万能脚本：把所有 `SSLContext.init` 传入的 TrustManager 换成什么都不检查的假货：

```javascript
Java.perform(function () {
  var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
  var TrustManager = Java.registerClass({
    name: 'com.fatdog.reverse.TrustBypass',
    implements: [X509TrustManager],
    methods: {
      checkClientTrusted: function () {},
      checkServerTrusted: function () {},
      getAcceptedIssuers: function () { return []; }
    }
  });
  var SSLContext = Java.use('javax.net.ssl.SSLContext');
  var init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
  init.implementation = function (km, tm, sr) {
    init.call(this, km, [TrustManager.$new()], sr);
  };
});
// 跑起来后 App 信任任何证书，mitmproxy 随便抓
```

（省事流：`objection -g com.fatdog.reverse android sslpinning disable` 同理。）

**答案**：加和 `51496`；flag `FLAG_18_L21{tls_custom_trust}`

---

## 关卡 22：双锁封疆（TrustManager + CertificatePinner 双闸门）

**考点**：在 L21 的自定义信任之上再叠一层 OkHttp `CertificatePinner`：把服务器证书的 **SPKI（公钥指纹）**焊死成 `sha256/Tix1…`，还加了个只认 `10.0.2.2/127.0.0.1/localhost` 的 HostnameVerifier。就算 Hook 掉 TrustManager 让代理证书被信任，pinner 发现证书指纹换了照样炸——**两道闸都要过**。

**类在哪**：`x2Activity` → `Pn.fetchPage`。`Pn.PIN` 就是 SPKI 指纹（明文字符串，可以直接看到）；HMAC 密钥 `Kp`（`fatdemo_`）+ `Pn.KB`（`pin_key`）。CA 复用 `Tm.caDer()`。诱饵 `Pim`。

**先读懂流程**：和 L21 一样，端点换成 `GET https://…:8443/api/pin`，密钥换 `fatdemo_pin_key`，响应明文 JSON。

**解法 A：静态复刻（推荐，最省事）**。pinner 只影响 OkHttp 客户端，你用 Python 带 CA 取数根本不经过它：

```python
import hmac, hashlib, json, ssl, time, urllib.request

KEY = b'fatdemo_pin_key'
ctx = ssl.create_default_context(cafile='certs/ca.crt')

def fetch(page):
    ts = int(time.time())
    msg = 'page=%d&ts=%d' % (page, ts)
    sign = hmac.new(KEY, msg.encode(), hashlib.sha256).hexdigest()
    url = 'https://127.0.0.1:8443/api/pin?page=%d&ts=%d&sign=%s' % (page, ts, sign)
    with urllib.request.urlopen(url, context=ctx) as r:
        obj = json.loads(r.read())
    return obj['nums']

total = 0
for p in range(1, 101):
    total += sum(fetch(p))
print(total)          # 50384
```

**解法 B：Frida 拆双闸门**。第一道同 L21（换掉 TrustManager），第二道 Hook `okhttp3.CertificatePinner.check` 让它空跑：

```javascript
Java.perform(function () {
  // 第一道：TrustManager 万能替换（同 L21）
  var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
  var TrustManager = Java.registerClass({
    name: 'com.fatdog.reverse.TrustBypass',
    implements: [X509TrustManager],
    methods: {
      checkClientTrusted: function () {},
      checkServerTrusted: function () {},
      getAcceptedIssuers: function () { return []; }
    }
  });
  var SSLContext = Java.use('javax.net.ssl.SSLContext');
  var init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
  init.implementation = function (km, tm, sr) { init.call(this, km, [TrustManager.$new()], sr); };

  // 第二道：OkHttp CertificatePinner 放行
  var CP = Java.use('okhttp3.CertificatePinner');
  CP.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, certs) {
    console.log('[L22] pinner bypass: ' + hostname);
  };
});
// 两道都过之后，mitmproxy 的假证书就能走通整条链路
```

（省事流：`objection -g com.fatdog.reverse android sslpinning disable` 会同时处理这两种检查。）

**答案**：加和 `50384`；flag `FLAG_18_L22{okhttp_certificate_pinner}`

---

## 关卡 23：白屏迷雾（WebView 自签证书错误）

**考点**：WebView 加载 HTTPS H5 页，证书自签、不在系统信任库 → `WebViewClient.onReceivedSslError` 被回调。App 在这里调 `handler.cancel()`——**页面白屏**。破解 = Hook 这个方法，改成调 `handler.proceed()` 放行。这是教程 21 的 WebView 分支，也是真实 App 里最常见的证书错误处理点。

**类在哪**：`y3Activity` + 具名内部类 `WvClient`；页面路径 `/h5/v23` 在 `Hq` 里异或 0x2F 藏着（主机由 `NetHost` 自动选）。诱饵 `WvKit`。**flag 不在 APK**，在服务端 H5 页面的 `<span id="flag">` 里。

**先读懂流程**：

```text
web.loadUrl("https://…:8443/h5/v23")            # 仅 HTTPS，HTTP 访问 403
→ onReceivedSslError(...) { handler.cancel(); }  # 白屏
→ （Hook 放行后）onPageFinished → evaluateJavascript 读 #flag → 庆祝 + 通关打点
```

**解法 A：静态抄近道**。电脑上无视证书错误直接看页面（`-k` 就等价于"proceed"）：

```bash
python server.py
curl -k https://127.0.0.1:8443/h5/v23     # 页面里 #flag 就是答案
```

**解法 B：Frida 正解**。Hook `com.fatdog.reverse.y3Activity$WvClient.onReceivedSslError`，把 `cancel` 换成 `proceed`：

```javascript
Java.perform(function () {
  var C = Java.use('com.fatdog.reverse.y3Activity$WvClient');
  C.onReceivedSslError.implementation = function (view, handler, error) {
    console.log('[L23] SSL 错误：' + error.getPrimaryError() + '，放行');
    handler.proceed();
  };
});
```

放行后页面出现，App 自动读 `#flag` 并触发庆祝 + 打点。

**解法 C：读懂原理版**。`SslErrorHandler` 只有两个选择：`proceed()`（无视错误继续加载）和 `cancel()`（终止加载）。真实 App 常在这里做白名单（只对自己域名 proceed），所以逆向时要重点看它判断域名的那段逻辑——哪些域名被放行、哪些被砍掉。

**答案**：flag `FLAG_18_L23{webview_ssl_error}`（这关没有求和要求，flag 只在服务端页面里）

---

## 关卡 24：换票迷局（反 Hook 检测 + 内存换 pin）

**考点**：pin 校验函数带"完整性守卫"——直接把校验 Hook 掉放行会被守卫抓住；正解是定位 pin 常量，用 Frida 把内置 pin 动态换成 mitmproxy 证书的 pin（**内存换票**）。这是教程 21 的"第 3 层最隐蔽打法"。

**类在哪**：

- `z24Activity`：关卡页（100 页 × 每页 10 个，分页取回求和）。
- `Aw`：OkHttp 客户端。自定义 TrustManager 只信内置 CA（复用 `Tm.caDer()`，所以 mitmproxy 证书先过不了第一关）；`HostnameVerifier.verify` 在这里算服务器证书 SPKI 并交给 pin 校验。
- `Z24Core`：pin 常量（XOR `^0x5A` 数组，无明文）+ `checkPin`/`assertGuard` 反 Hook 守卫。
- `Tk`：HMAC 密钥前半段 `fatdemo_`；`Aw.KB` 是后半段 `swap_key`，拼出 `fatdemo_swap_key`。
- 诱饵 `Gp`：一个"假 pin + 假放行"的工具类，没有任何人调用它——最先翻到它的人最容易掉坑。

**先读懂流程**：

```text
loadPage → Aw.fetchPage(base, page)
  → 自定义 TrustManager 只信内置 CA（复用 Tm.caDer()，mitmproxy 证书过不了第一关）
  → HostnameVerifier.verify(host, session):
        spki = Z24Core.spkiSha256(服务器证书)      # "sha256/" + Base64(SHA-256(公钥 DER))
        return Z24Core.checkPin(spki)
              # checkPin 内部：guardTicks++ → lastVerdict = realPin().equals(spki)
  → 响应到达、解析前：Z24Core.assertGuard()
        # guardTicks==0 或 lastVerdict==false → 抛"完整性校验失败：校验链被篡改"
```

**考点拆解（守卫是怎么抓人的）**：

- 把 `verify` 或 `checkPin` 整个 Hook 掉、直接 return true → 原函数没跑，`guardTicks` 一直是 0 → `assertGuard` 抛异常，页面显示"完整性校验失败"。
- 就算 Hook `checkPin` 时先调了原函数、再强行 return true（配合 mitmproxy）→ 原函数里 `lastVerdict` 是 false（假证书指纹对不上真 pin）→ `assertGuard` 照样抛。
- 正确姿势：**别动校验逻辑，只换"对比的标准"**——Hook `Z24Core.realPin` 的返回值，换成 mitmproxy 证书自己的 SPKI pin。校验链照常走完：计数正常、结论为真。

**解法 A：静态复刻（最省事）**。pin 只保护 App 的 OkHttp 客户端，你用 Python 带 CA 取数根本不经过它：

```python
import hmac, hashlib, json, ssl, time, urllib.request

KEY = b'fatdemo_swap_key'
ctx = ssl.create_default_context(cafile='certs/ca.crt')

def fetch(page):
    ts = int(time.time())
    msg = 'page=%d&ts=%d' % (page, ts)
    sign = hmac.new(KEY, msg.encode(), hashlib.sha256).hexdigest()
    url = 'https://127.0.0.1:8443/api/swap?page=%d&ts=%d&sign=%s' % (page, ts, sign)
    with urllib.request.urlopen(url, context=ctx) as r:
        obj = json.loads(r.read())
    return obj['nums']

total = 0
for p in range(1, 101):
    total += sum(fetch(p))
print(total)          # 50225
```

（密钥还原：`Tk.PA` 每字节 `^0x3C` → `fatdemo_`，`Aw.KB` 每字节 `^0x3C` → `swap_key`。）

**解法 B：Frida script E——内存换票（本关正解，配合 mitmproxy）**：

第一步，先拿到 mitmproxy 证书自己的 SPKI pin：

```bash
openssl x509 -in ~/.mitmproxy/mitmproxy-ca-cert.pem -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64
# 得到一串 Base64（43 个字符 + '='），前面手动拼上 "sha256/" 就是新 pin
```

第二步，注入 script E。第一关同 L21 换掉 TrustManager（否则 mitmproxy 证书连信任关都过不去），第二关才是本关独有的**换票**：

```javascript
// swap_pin.js —— script E：内存换票
Java.perform(function () {
  // 第一关：TrustManager 万能替换（同 L21）
  var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
  var TrustManager = Java.registerClass({
    name: 'com.fatdog.reverse.TrustBypass24',
    implements: [X509TrustManager],
    methods: {
      checkClientTrusted: function () {},
      checkServerTrusted: function () {},
      getAcceptedIssuers: function () { return []; }
    }
  });
  var SSLContext = Java.use('javax.net.ssl.SSLContext');
  var init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
  init.implementation = function (km, tm, sr) { init.call(this, km, [TrustManager.$new()], sr); };

  // 第二关：换票——把内置 pin 换成 mitmproxy 证书的 SPKI pin
  var Z24 = Java.use('com.fatdog.reverse.Z24Core');
  Z24.realPin.implementation = function () {
    return 'sha256/<换成你的 mitmproxy 证书 SPKI>';
  };
});
```

注入后正常翻页：`verify` 算出来的是 mitmproxy 证书的 SPKI，`checkPin` 拿它和换过的 pin 一比——相等，`lastVerdict=true`，`assertGuard` 放行。流量全过 mitmproxy，100 页数据在代理里一览无余。

**防坑提醒**：

- `Gp.FAKE_PIN` 是诱饵，直接拿它换必挂（它和服务器指纹对不上）。
- 别 Hook `checkPin` 强制返回 true：守卫会抛"完整性校验失败"。
- 换票前先确认第一关（信任）真的放行了，否则 `verify` 根本进不去。
- 再往下推一层：守卫本身也能被 Hook（把 `assertGuard` 清空就行）——所以真实世界里反 Hook 永远是和攻击者的军备竞赛，检测点要尽量藏、尽量多，单一检测点拦不住有心人。

**答案**：加和 `50225`；flag `FLAG_18_L24{anti_hook_pin_swap}`

---

## 关卡 25：灵台证真（JNI native 校验，教程 22 预告）

**考点**：这一关把"门禁 + 签名"整段搬进了 `libnative.so`。jadx 里只有两行 `native` 声明，Java 层 Hook 什么都拿不到——签名根本不经过 Java。这是教程 22（native 逆向）的入门预告，所以难度刻意压低：**密钥没加密，strings 就能看到**。

**类在哪**：

- `a25Activity`：关卡页（100 页 × 每页 10 个，分页取回求和）。
- `Nx`：JNI 桥。`System.loadLibrary("native")` + 两个声明：`verifyServer(String)`、`nativeSign(int, long)`。
- `By`：OkHttp 客户端，调 `Nx` 两个方法后发 `GET /api/native`。
- `Rj`：诱饵（假密钥 `fatdemo_fake_key_java`，没人调用）。
- 真身：APK 里的 `lib/arm64-v8a/libnative.so`、`lib/armeabi-v7a/libnative.so`（源码 `app/jni/native.c`）。

**先读懂流程**：

```text
loadPage → By.fetchPage
  → Nx.verifyServer(host)     # C：白名单 10.0.2.2 / 127.0.0.1 / localhost
  → Nx.nativeSign(page, ts)   # C：HMAC-SHA256("fatdemo_jni_2026", "page=N&ts=T") 十六进制
  → OkHttp GET https://…:8443/api/native?page=N&ts=T&sign=...（自定义信任，内置 CA）
```

**为什么 Java Hook 无效**：`Mac`/`MessageDigest` 的 Hook 一个都不会触发（HMAC 在 C 里实现）；jadx 里也没有密钥。要动它，要么静态读 so，要么 Frida 上原生层。

**解法 A：静态（推荐，本关入门难度）**。APK 就是个 zip：

```bash
# 解出 so（Windows 上改后缀 .zip 直接解压，或用 unzip）
unzip FatdogReverse.apk 'lib/arm64-v8a/libnative.so' -d /tmp/l25
strings /tmp/l25/lib/arm64-v8a/libnative.so | grep fatdemo
# → fatdemo_jni_2026   （密钥明文躺在 so 里）

# 顺便看看导出的函数名（Frida 要用）：
nm -D /tmp/l25/lib/arm64-v8a/libnative.so | grep Nx
```

拿到密钥后 Python 带 CA 复刻（门禁和签名都只保护 App 自己，拦不住 Python）：

```python
import hmac, hashlib, json, ssl, time, urllib.request

KEY = b'fatdemo_jni_2026'
ctx = ssl.create_default_context(cafile='certs/ca.crt')

def fetch(page):
    ts = int(time.time())
    msg = 'page=%d&ts=%d' % (page, ts)
    sign = hmac.new(KEY, msg.encode(), hashlib.sha256).hexdigest()
    url = 'https://127.0.0.1:8443/api/native?page=%d&ts=%d&sign=%s' % (page, ts, sign)
    with urllib.request.urlopen(url, context=ctx) as r:
        obj = json.loads(r.read())
    return obj['nums']

total = 0
for p in range(1, 101):
    total += sum(fetch(p))
print(total)          # 52674
```

**解法 B：Frida 原生层**。Java 层不管用，就上 `Interceptor` / `NativeFunction`：

```javascript
// l25_native.js
Java.perform(function () {
  var env = Java.vm.getEnv();

  // 1) 观察签名：App 每次翻页都会经过这里
  var addr = Module.findExportByName('libnative.so', 'Java_com_fatdog_reverse_Nx_nativeSign');
  Interceptor.attach(addr, {
    onEnter: function (args) {
      console.log('[nativeSign] page=' + args[2].toInt32() + ' ts=' + args[3].toInt64());
    },
    onLeave: function (retval) {
      console.log('[nativeSign] ret=' + env.getStringUtfChars(retval, ptr(0)).readCString());
    }
  });

  // 2) 把 native 函数当工具用：先过门禁，再拿任意页的签名
  var verAddr = Module.findExportByName('libnative.so', 'Java_com_fatdog_reverse_Nx_verifyServer');
  var verifyServer = new NativeFunction(verAddr, 'int', ['pointer', 'pointer', 'pointer']);
  var nativeSign = new NativeFunction(addr, 'pointer', ['pointer', 'pointer', 'int', 'long']);
  var jstr = env.newStringUtf('127.0.0.1');
  console.log('verifyServer =', verifyServer(env.handle, ptr(0), jstr.handle));

  rpc.exports.sign = function (page, ts) {
    var r = nativeSign(env.handle, ptr(0), page, ts);
    return env.getStringUtfChars(r, ptr(0)).readCString();
  };
});
// frida -U -n com.fatdog.reverse -l l25_native.js
// 控制台里：rpc.exports.sign(1, 123) → 92bf819c0e889a884493c891b6701334032762a1d2309b1795bd555f682bf712
```

拿到签名后，和解法 A 一样拼 URL 取满 100 页。

**解法 C：改返回值 / patch so**。`Interceptor.attach(verifyServer)` 的 `onLeave` 里 `retval.replace(1)` 可以放行白名单外的主机（比如把 config.json 指到局域网 IP 时用）；直接把 so 里的白名单字符串 patch 掉也一样。真机上改 so 记得重打包重签名。

**防坑提醒**：

- `Rj.FAKE_KEY` 是诱饵，用它算签名必 403。
- Hook `Mac.doFinal` / `MessageDigest.update` 白搭：本关 HMAC 在 C 里，Java 根本没有这些调用。
- `verifyServer` 只认 10.0.2.2 / 127.0.0.1 / localhost：把 config.json 指到别的 IP 会先被门禁拦住。
- 自校验向量：`HMAC(fatdemo_jni_2026, "page=1&ts=123")` = `92bf819c0e889a884493c891b6701334032762a1d2309b1795bd555f682bf712`——自己复刻完先拿它对比。

**答案**：加和 `52674`；flag `FLAG_18_L25{native_jni_verify}`

---
## 附：smali 关卡通用操作速查（7-9、20 关）

```text
apktool d FatdogReverse.apk -o out       # 单 classes.dex → out/smali（已无 classes2/3）
apktool b out -o rebuilt.apk
zipalign -f 4 rebuilt.apk aligned.apk
apksigner sign --ks build/debug.keystore --ks-key-alias androiddebugkey \
        --ks-pass pass:android --key-pass pass:android --out patched.apk aligned.apk
adb install -r patched.apk
```

## 附：Frida 关卡通用操作速查（10-15 关 + 21-25 抓包关）

```text
# PC 端
pip install frida-tools
frida --version                 # 记下版本

# 设备端（root 模拟器/真机，版本必须和 PC 一致）
adb push frida-server /data/local/tmp/fs
adb shell "su -c 'chmod 755 /data/local/tmp/fs && /data/local/tmp/fs &'"
frida-ps -U                     # 能列进程 = 环境通

# 跑脚本（attach 运行中的 App，用包名最稳）
frida -U -n com.fatdog.reverse -l hook_l10.js

# 更省事：直接 Hook 每个 Activity 的 verify() 强制返回 true，一关直接通
```

## 附：所有 flag 速查表

| 关卡 | flag |
|---|---|
| 1 | `FLAG_18_L1{plain_text_in_dex}` |
| 2 | `FLAG_18_L2{base64_is_not_encryption}` |
| 3 | `FLAG_18_L3{xor_puzzle}` |
| 4 | `FLAG_18_L4{md5_123456}` |
| 5 | `FLAG_18_L5{config_json_assets}` |
| 6 | `FLAG_18_L6{exported_activity}` |
| 7 | `FLAG_18_L7{smali_vip_bypass}` |
| 8 | `FLAG_18_L8{smali_activation_key}` |
| 9 | `FLAG_18_L9{multi_gate_cleared}` |
| 10 | `FLAG_18_L10{sha256_gate_cleared}` |
| 11 | `FLAG_18_L11{hmac_sign_passed}` |
| 12 | `FLAG_18_L12{aes_vault_unlocked}` |
| 13 | `FLAG_18_L13{dual_param_dual_alg}` |
| 14 | `FLAG_18_L14{triple_layer_chain}` |
## 关卡 26：双符合璧（双向 TLS / mTLS，客户端证书）

**题面**：这一关服务端在 **TLS 握手层强制验证客户端证书**（双向 TLS / mTLS）。App 不光要验服务端（内置 CA），还要**出示自己的客户端证书+私钥**——少一张，握手直接失败。抓包工具没这证书，连明文都看不到；想复刻取数，得先把 APK 里的证书"抠"出来。

**考点**：客户端证书提取、PKCS12、mTLS 原理。

**涉及类**：

- `b26Activity`：关卡页（100 页 × 每页 10 个，分页取数求和）。
- `Vd`：OkHttp 客户端。信任侧沿用内置 CA（`Tm.caDer()`）；出示侧用 `Mc.loadP12()` 产出 KeyManager，握手时自动出示客户端证书链。端点 `https://…:8444/api/mtls`。
- `Zt`：HMAC 密钥前半段（^0x3C）**兼** PKCS12 密码前半段（^0x37）。
- `Mc`：PKCS12 保险库。密码后半段（^0x5B）在本类，运行时拼出完整密码打开 `assets/mt_client.p12`。
- `MtlsKit`：**诱饵**（假密码 `client_secret_26`、假别名，无人调用）。
- 服务端：`:8444` 独立 app 实例 + `ssl_cert_reqs=CERT_REQUIRED`（信任 `certs/ca.crt` 签发的客户端证书）。注意 `/api/mtls` **不在** 8787/8443 上——想不带证书从老端口绕过是死路（404）。

**调用链路**：

```text
loadPage → Vd.fetchPage
  ├─ Mc.buildPassword() = Zt.pxa()(^0x37) + decodePXB()(^0x5B)   # "fatdemo_" + "mt26"
  ├─ KeyStore("PKCS12").load(assets/mt_client.p12, password)      # 别名 fatdog-client
  ├─ SSLContext.init(KeyManagers, TrustManagers(Tm.caDer()), …)   # 双向都齐了
  └─ GET https://…:8444/api/mtls?page=N&ts=T&sign=HMAC-SHA256(Zt.pa()+Vd.kb(), "page=N&ts=T")
```

**解法 A：静态提取 + Python 复刻（推荐，零依赖设备）**：

1. 解出两组 XOR 数组：`Zt.PA`(^0x3C→`fatdemo_`) + `Vd.KB`(^0x3C→`mtls_key`) = HMAC 密钥 `fatdemo_mtls_key`；`Zt.PXA`(^0x37→`fatdemo_`) + `Mc.PXB`(^0x5B→`mt26`) = p12 密码 `fatdemo_mt26`。
2. 把 APK 当 zip 解开，拿走 `assets/mt_client.p12`（也可 `keytool -list -v -keystore mt_client.p12 -storetype PKCS12` 查看别名）。
3. Python 复刻（带客户端证书 + 内置 CA，100 页求和 = `50814`）：

```python
# solve_l26.py —— pip install cryptography
import hashlib, hmac, json, ssl, time, zipfile, io, os, tempfile
import urllib.request
from cryptography.hazmat.primitives.serialization import (
    pkcs12, Encoding, PrivateFormat, NoEncryption)

APK = 'FatdogReverse.apk'
CA = 'certs/ca.crt'          # server.py 仓库里自带的内置 CA
KEY26 = b'fatdemo_mtls_key'

p12 = zipfile.ZipFile(APK).read('assets/mt_client.p12')   # 密码 fatdemo_mt26
key, cert, _ = pkcs12.load_key_and_certificates(p12, b'fatdemo_mt26')
d = tempfile.mkdtemp()
crt_p, key_p = os.path.join(d, 'c.pem'), os.path.join(d, 'k.pem')
open(crt_p, 'wb').write(cert.public_bytes(Encoding.PEM))
open(key_p, 'wb').write(key.private_bytes(Encoding.PEM,
        PrivateFormat.TraditionalOpenSSL, NoEncryption()))

ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA)
ctx.load_cert_chain(crt_p, key_p)                          # mTLS 的"我方名帖"

total = 0
for page in range(1, 101):
    ts = int(time.time())
    sign = hmac.new(KEY26, f'page={page}&ts={ts}'.encode(), hashlib.sha256).hexdigest()
    url = f'https://127.0.0.1:8444/api/mtls?page={page}&ts={ts}&sign={sign}'
    obj = json.load(urllib.request.urlopen(url, context=ctx, timeout=5))
    total += sum(obj['nums'])
print(total)   # 50814
```

> 真机环境把 `127.0.0.1` 换成 `adb reverse tcp:8444 tcp:8444` 后的地址即可。

**解法 B：Frida 动态拿密码 / 抓包**：

```javascript
// 在发包瞬间把 p12 密码整个倒出来
Java.perform(function () {
    var Mc = Java.use('com.fatdog.reverse.Mc');
    console.log('p12 pass =', Mc.buildPassword());   // fatdemo_mt26
});
```

拿到密码后解开 p12 得到 client.crt/client.key，mitmproxy 即可配置上游 mTLS：
`mitmdump -p 8080 --set upstream_cert=false --ssl-insecure -s xxx.py`，
或直接给 mitmproxy 加 `--set connection_strategy=lazy` + 自定义 addon 在 `tls_connect` 里挂上客户端证书上下文（`context.client_certfile = ...`）。抓到明文后按 L21 的路子复刻签名取数。

**为什么不能硬碰**：没有客户端证书，TLS ClientHello 后的 CertificateRequest 阶段就谈崩，任何 Hook HTTP 层的手段都没用——这就是"双符合璧"的门槛。

---

## 关卡 27：万法归宗（抓包→复刻全闭环）

**题面**：这一关把双闸门和复合签名合到一起：HTTPS + 证书锁定挡在门外，请求参数 AES 整段加密 + HMAC 签名、响应体再加密。这一关想教你的是——**抓到明文≠采集成功**：就算放倒 pinning 把包抓了，看到的也只是 enc 密文；必须还原整条签名链复刻发包，才能取满 100 页求和。

**考点**：混淆识别、字符串解密、密钥拆段拼装、TLS 双闸门绕过、签名链复刻。

**涉及类**：

- `c27Activity`：关卡页（100 页 × 每页 10 个，分页取数求和）。**全关唯一可读的入口**，调用链从这里进混淆包。
- `p/Wire`：网络核心。`enc = hex(AES(req_key, "page=N&ts=T"))`、`sign = HMAC-SHA256(hmac_key, enc)`，POST 表单带 page/ts/enc/sign + client/chan/ver/dev 噪声字段；响应 `{"d": hex}` 用 rsp_key 解密成 `page=N|nums=…`。
- `p/Gate`：TLS 双闸门。TrustManager 信内置 CA（`Tm.caDer()`）+ CertificatePinner 焊死 SPKI（pin 以 ^0x27 数组藏在素材库，无明文 sha256/）。
- `p/Cpt`：加密原语（AES-ECB/PKCS5Padding + HmacSHA256），算法名以 ^0x31 数组藏着。
- `p/Mk` / `p/Tail`：三把密钥各拆两半跨类拼装（全部 ^0x3C）：`fatdemo_`（Mk）+ `aeskey27` / `fin_hmac` / `rspkey27`（Tail）；路径 `/api/l27` 是 ^0x25 数组。
- **R8 混淆**：p 包不在 r8.pro 的 keep 名单里，jadx 里全是 a/b/c 短名——先按角色认类（谁调 Cipher 谁是原语、谁建 OkHttpClient 谁是 TLS 客户端）。
- 诱饵双份：包内 `p/Gh`（假密钥假 pin，跟着一起被混淆）+ 根包 `EndKit`（假密钥 `fatdemo_end_fake_ky`、假端点 `/api/end`）。
- 服务端：`POST https://…:8443/api/l27`，验 ts → 验 HMAC → AES 解 enc 核对 page/ts → 返回 AES 加密的 body。

**调用链路**：

```text
loadPage → p.Wire.fetchPage
  ├─ p.Gate.get()
  │    ├─ TrustManager(Tm.caDer())            # 第一道闸
  │    └─ CertificatePinner(host, Mk.pin())   # 第二道闸（pin 无明文）
  ├─ Cpt.aesEncode("page=N&ts=T", Mk.pre()+Tail.T_REQ)    # "fatdemo_aeskey27"
  ├─ Cpt.hmacSign(enc, Mk.pre()+Tail.T_HMAC)              # "fatdemo_fin_hmac"
  └─ POST https://…:8443/api/l27 (page/ts/enc/sign/…)
       ← {"d": hex} → Cpt.aesDecode(d, Mk.pre()+Tail.T_RSP) # "fatdemo_rspkey27"
```

**解法 A：静态还原 + Python 复刻（推荐）**：

1. jadx 打开 APK，从可读的 `c27Activity` 找到对混淆包的调用，交叉引用认出 Wire/Gate/Cpt/Mk/Tail 五个角色。
2. 解出三组 XOR 数组并拼装密钥：`Mk.S_PRE`^0x3C + `Tail.T_REQ`^0x3C = `fatdemo_aeskey27`；同法得 `fatdemo_fin_hmac`、`fatdemo_rspkey27`；路径 `Mk.S_PATH`^0x25 = `/api/l27`。
3. Python 复刻（带内置 CA，POST 表单，100 页求和 = **50623**）：

```python
# solve_l27.py —— pip install pycryptodome
import hashlib, hmac, json, ssl, time, urllib.request, urllib.parse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY_AES_REQ = b'fatdemo_aeskey27'   # Mk.pre() + Tail.T_REQ
KEY_HMAC    = b'fatdemo_fin_hmac'   # Mk.pre() + Tail.T_HMAC
KEY_AES_RSP = b'fatdemo_rspkey27'   # Mk.pre() + Tail.T_RSP

ctx = ssl.create_default_context(cafile='certs/ca.crt')
ctx.check_hostname = False          # 只校验信任链即可

total = 0
for page in range(1, 101):
    ts   = int(time.time())
    enc  = AES.new(KEY_AES_REQ, AES.MODE_ECB).encrypt(
               pad(f'page={page}&ts={ts}'.encode(), 16)).hex()
    sign = hmac.new(KEY_HMAC, enc.encode(), hashlib.sha256).hexdigest()
    data = urllib.parse.urlencode({'page': page, 'ts': ts, 'enc': enc,
                                   'sign': sign, 'client': 'android-fatdemo',
                                   'chan': 'final', 'ver': '2.7', 'dev': '0'*16}).encode()
    req = urllib.request.Request('https://127.0.0.1:8443/api/l27', data=data,
                                 headers={'Content-Type': 'application/x-www-form-urlencoded'})
    obj = json.load(urllib.request.urlopen(req, context=ctx, timeout=5))
    clear = unpad(AES.new(KEY_AES_RSP, AES.MODE_ECB)
                  .decrypt(bytes.fromhex(obj['d'])), 16).decode()      # page=N|nums=a,b,...
    total += sum(int(x) for x in clear.split('|')[1].split('=')[1].split(','))
print(total)   # 50623
```

> 真机环境把 `127.0.0.1` 换成 `adb reverse tcp:8443 tcp:8443` 后的地址即可。

**解法 B：Frida 放倒双闸门抓包（体会"抓到明文≠采集成功"）**：

```javascript
Java.perform(function () {
    // 1) TrustManager 那道闸：换成全信任（或 objection android sslpinning disable 一把梭）
    // 2) Pinner 那道闸：OkHttp 的 check$okhttp 直接置空
    var CP = Java.use('okhttp3.CertificatePinner');
    CP.check.overload('java.lang.String', 'java.util.List').implementation = function (h, p) {
        console.log('[pinner bypass]', h);
        return;   // 不抛 CertificateException 即放行
    };
});
```

放倒两道闸后 mitmproxy 能抓到请求——但表单里只有 enc 密文。此时两条路：
要么继续 Hook 解密后的返回（Hook 混淆后的 aesDecode 观察明文 `page=N|nums=…`，一页页攒数据）；
要么回到静态路线解出三把密钥，用脚本一次取满。后者才是"复刻"的完整形态。

**为什么叫万法归宗**：这关串起了第一季到第二季的全套技能——搜入口 → 认混淆 → 解 XOR → 绕 pinning → 复刻签名链。四步少一步都拿不到 50623。



| 15 | `FLAG_18_L15{thousand_number_sum}`（答案=加和 `49580`） |
| 16 | `FLAG_18_L16{rc4_stream_encrypted}`（答案=加和 `24074`） |
| 17 | `FLAG_18_L17{sm4_sm3_form}`（答案=加和 `50636`） |
| 18 | `FLAG_18_L18{rsa_des_form}`（答案=加和 `51258`） |
| 19 | `FLAG_18_L19{obfuscated_aes_hmac}`（答案=加和 `51648`） |
| 20 | `FLAG_18_L20{ads_are_gone}`（无口令：改 `AdBox.a` 开关即通） |
| 21 | `FLAG_18_L21{tls_custom_trust}`（答案=加和 `51496`） |
| 22 | `FLAG_18_L22{okhttp_certificate_pinner}`（答案=加和 `50384`） |
| 23 | `FLAG_18_L23{webview_ssl_error}`（在 H5 页面 #flag 里直接可见） |
| 24 | `FLAG_18_L24{anti_hook_pin_swap}`（答案=加和 `50225`） |
| 25 | `FLAG_18_L25{native_jni_verify}`（答案=加和 `52674`） |
| 26 | `FLAG_18_L26{mutual_tls_client_cert}`（加和 `50814`） |
| 27 | `FLAG_18_L27{capture_then_replicate}`（答案=加和 `50623`） |

> 关卡 9 的 else 分支里那个 `FLAG_18_L9{single_gate_not_enough}` 是诱饵，不是有效 flag。


---

## 关卡 28：缄默之钥（native 字符串加密）

**考点**：密钥 `Fatdog_unhappy` 被 ^0x5C 存成字节数组 `KEY28_KX` 躺在 libl28.so 的 .rodata，运行时才解到栈缓冲喂 HMAC-SHA256。strings 只能看到诱饵 `Fatdog_silent`（Java 层 `Fk.FAKE_KEY` 与 so 内 `KEY28_DECOY` 双份埋伏）。

**静态路线**
1. 解包 APK 取 `lib/arm64-v8a/libl28.so`；`strings libl28.so | grep Fatdog` 只见诱饵。
2. IDA/Ghidra 打开：导出表有 `Java_com_fatdog_reverse_Zk_nativeSign` 和数组符号 `KEY28_KX`；跟一遍函数开头的解码循环（每字节 ^0x5C）即还原密钥 `Fatdog_unhappy`。
3. Python 复刻（先 `python server.py`，本目录执行）：

```python
import time, hmac, hashlib, requests

KEY  = b"Fatdog_unhappy"                # IDA 还原出的真密钥
BASE = "https://127.0.0.1:8443"         # 模拟器换 https://10.0.2.2:8443
CA   = "certs/ca.crt"

total = 0
for page in range(1, 101):
    ts   = int(time.time())             # 服务端有 600s 新鲜度窗口
    sign = hmac.new(KEY, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()
    r = requests.get(f"{BASE}/api/l28", params={"page": page, "ts": ts, "sign": sign},
                     verify=CA, timeout=10)
    total += sum(r.json()["nums"])
print("总和:", total)                    # 49750
```

对拍样例（本机已实算）：`HMAC(Fatdog_unhappy, "page=1&ts=1787013761") = 6e05345fe471e618e1691e86d995edaf64a60b074bced900b3a0e5fcc01ea057`，可与 Frida 观察到的返回值逐字符比对。

**Frida 动态路线**

```javascript
// hook_l28.js —— 三联单观察 nativeSign（so 未加载时等 dlopen）
function hookSign() {
  var addr = Module.findExportByName('libl28.so', 'Java_com_fatdog_reverse_Zk_nativeSign');
  if (!addr) return false;
  Interceptor.attach(addr, {
    onEnter: function (a) { this.page = a[2].toInt32(); this.ts = a[3].toString(10); },
    onLeave: function (rv) {
      var env = Java.vm.getEnv();
      var chars = env.getStringUtfChars(rv, NULL);
      console.log('[nativeSign] page=' + this.page + ' ts=' + this.ts + ' → ' + chars.readUtf8String());
      env.releaseStringUtfChars(rv, chars);
    }
  });
  return true;
}
Java.perform(function () {
  if (!hookSign()) ['android_dlopen_ext', 'dlopen'].forEach(function (fn) {
    var p = Module.findExportByName(null, fn); if (!p) return;
    Interceptor.attach(p, {
      onEnter: function (a) { this.n = a[0].readCString(); },
      onLeave: function () { if (this.n && this.n.indexOf('libl28.so') >= 0) hookSign(); }
    });
  });
});
// 另一条路：运行时内存里搜解出来的明文密钥
// var m = Process.findModuleByName('libl28.so');
// Memory.scanSync(m.base, m.size, '46 61 74 64 6f 67 5f 75 6e 68 61 70 70 79')  // "Fatdog_unhappy"
```

**坑位提醒**：`Fk.FAKE_KEY` 和 so 里明文可见的 `Fatdog_silent` 都是诱饵，拿来算签名只会收到 403。

---

## 关卡 29：隐姓埋名（native 动态注册）

**考点**：真身经 `JNI_OnLoad → RegisterNatives` 动态绑定到 Wq.nativeSign——实现是无名 static 函数，导出表里没有任何"正确名字"的真函数。两个带名字的导出全是坑：

| 导出函数 | 真面目 |
|---|---|
| `Java_com_fatdog_reverse_Wq_nativeSign` | 名字完全符合静态注册规则，但被动态注册覆盖、JVM 永不调用；内部用明文假钥 `Fatdog_lazy`（strings 可见），手动 NativeFunction 调它得错值 → 403 |
| `Java_com_fatdog_reverse_Wq_sign` | 方法名都对不上，返回固定废 hex |

另有 Java 层诱饵 `Yd.FAKE_KEY="Fatdog_bogus"`。真密钥 `Fatdog_angry` 以 ^0x69 数组 `KEY29_KX` 藏在 .data。

**Frida 动态路线（正路）**

```javascript
// hook_rn.js —— spawn 注入（frida -U -f com.fatdog.reverse -l hook_rn.js，CLI 敲 %resume 放行）
Java.perform(function () {
  var sym  = '_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi';
  var addr = Module.findExportByName('libart.so', sym);
  Interceptor.attach(addr, {
    onEnter: function (args) {
      var methods = args[2], count = args[3].toInt32();
      for (var i = 0; i < count; i++) {
        var m = methods.add(i * 24);          // 64 位：name/sig/fnPtr 各 8 字节
        console.log('[RegisterNatives] ' + m.readPointer().readCString()
          + m.add(8).readPointer().readCString() + ' → ' + m.add(16).readPointer());
      }
    }
  });
});
// 抓到映射后按偏移挂三联单：
// var mod = Process.findModuleByName('libl29.so');
// Interceptor.attach(mod.base.add(偏移), { onEnter/onLeave 见关卡 28 脚本 })
```

拿到三联单里的签名后与本地试算对拍，确认消息格式 `page=N&ts=T`。

**静态路线**

IDA 从 `JNI_OnLoad` 入手：`FindClass("com/fatdog/reverse/Wq")` 后的 `RegisterNatives(env, cls, methods, 1)`，methods 数组第三格就是无名真身地址；顺带看到 `.data` 里的 `KEY29_KX`（12 字节，逐字节 ^0x69 还原 `Fatdog_angry`）。复刻脚本与关卡 28 相同，只换 KEY 为 `b"Fatdog_angry"`、端点为 `/api/l29`，100 页求和 = **50208**。
