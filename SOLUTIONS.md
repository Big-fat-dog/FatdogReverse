# FatdogReverse · 完整题解（按分类组织 · 不分季）

> 建议每关至少独立卡 10 分钟再看对应小节。闯关的意义是练出「先搜什么、再看什么、最后用什么工具」的肌肉记忆，而不是抄答案。
> 本文按 App 内的关卡分类组织正文（静态分析 → Smali → Frida → 网络对抗 → SSL 抓包 → Native → Xposed → 签名校验 → 天地秘境六卷），不再区分"第几季"。编号即关卡真名：主流程 `L1-L47`，天地秘境 `KL1-KL40`，太玄之初追加卷 `KKL1-KKL5`（全五关已开启）。关卡 6 没有入口按钮，藏在 Manifest；关卡 20 虽是 20 号，主题属 Smali 挑战，故排在 Smali 分类。

## 关卡总览

| 分类 | 关卡 | 正文位置 |
|---|---|---|
| 静态分析 | L1-L6 | `## 静态分析（L1-6）` |
| Smali 挑战 | L7-L9、L20 | `## Smali 挑战（L7-9、L20）` |
| Frida Hook（Java 层） | L10-L14 | `## Frida Hook · Java 层（L10-14）` |
| 网络对抗 | L15-L19 | `## 网络对抗（L15-19）` |
| SSL 抓包 | L21-L27 | `## SSL 抓包（L21-27）` |
| Native 试炼 | L28-L37 | `## Native 试炼（L28-37）` |
| Xposed 实战 | L38-L42 | `## Xposed 实战（L38-42）` |
| 签名校验对抗 | L43-L47 | `## 签名校验对抗（L43-47）` |
| 天地秘境 · 昆仑山 | KL1-KL5 | `## 天地秘境 · 昆仑山（KL1-5）` |
| 天地秘境 · 流沙河 | KL6-KL10 | `## 天地秘境 · 流沙河（KL6-10）` |
| 天地秘境 · 幽冥海 | KL11-KL15 | `## 天地秘境 · 幽冥海（KL11-15）` |
| 天地秘境 · 太玄之初 | KL16-KL20、KKL1-KKL5 | `## 天地秘境 · 太玄之初（KL16-20、KKL1-5）` |
| 天地秘境 · 扶桑树 | KL21-KL28 | `## 天地秘境 · 扶桑树（KL21-28）` |
| 天地秘境 · 天机阁 | KL29-KL30 | `## 天地秘境 · 天机阁（KL29-30）` |
| 天地秘境 · 碧落天 | KL36-KL40 | `## 天地秘境 · 碧落天（KL36-40）` |

> 网络/服务端类关卡（L15-L47 与 KL6-KL10、KKL2-KKL4）的加和答案以各节正文为准；服务端先 `python server.py` 起 HTTPS（21 起）才能取数。

## 静态分析（L1-6）


### 关卡 1：明文藏宝

**考点**：字符串常量在 dex 里永远是明文——这是整个逆向的地基。

**解法**：
1. jadx 打开 `FatdogReverse.apk`（GUI 版直接双击，或命令行 `jadx -d out FatdogReverse.apk`）。
2. 菜单/快捷键全文搜索 `FLAG_18`。
3. 命中 `TokenVaultActivity.java`，flag 就写死在 `final String flag` 里。

**答案**：`FLAG_18_L1{plain_text_in_dex}`

---


### 关卡 2：Base64 马甲

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


### 关卡 3：拼图游戏

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


### 关卡 4：MD5 验门

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

**答案**：`123456`

---


### 关卡 5：资源藏宝

**考点**：APK 本质是 zip；便宜的信息常躺在最浅的地方（assets/）。

**解法**：
1. `FatdogReverse.apk` 复制一份改后缀为 `.zip`，解压。
2. 打开 `assets/config.json`，`feature.treasure_note` 字段就是 flag。
3. （jadx 的"资源"面板也能直接看到，不用解压。）

**答案**：`FLAG_18_L5{config_json_assets}`

---


### 关卡 6：隐藏入口

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


## Smali 挑战（L7-9、L20）


### 关卡 7：VIP 检测（smali）—— 去掉 isVip 检测

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
apksigner sign --ks keystore/debug.keystore --ks-key-alias androiddebugkey \
        --ks-pass pass:android --key-pass pass:android --out patched.apk aligned.apk
adb install -r patched.apk
```

5. 打开点"查看会员内容" → 出 flag。

**答案**：`FLAG_18_L7{smali_vip_bypass}`

---


### 关卡 8：激活码（smali）—— 还原 fill-array-data 或改 checkKey

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


### 关卡 9：多重资格（smali）—— 两个检查 + 诱饵

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


### 关卡 20：万恶广告劫（smali，关不掉的牛皮癣广告）

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


## Frida Hook · Java 层（L10-14）



### 关卡 10：SHA-256 验门（Frida 第 1 关）

**考点**：SHA-256 只做完整性校验，不直接比对外部口令；种子分片异或藏匿，还原后才能通过。

**静态解法**：
1. jadx 看 `HashCheckActivity.verify()`：`sha256Hex(seed)` 与 `HashSeed.sha256Fingerprint()` 比对。
2. 种子不在外部知识里：进 `HashSeed`，两段字节数组分别 `^0x33`、`^0x5A`，拼接还原即为正确口令。
3. Python 复刻验证：

```python
import hashlib
def dec(a, k):
    return bytes(x ^ k for x in a).decode()
seed = dec([85,65,90,87], 0x33) + dec([59], 0x5A)
print(seed)                              # 需要自己还原
print(hashlib.sha256(seed.encode()).hexdigest())  # db77...73846
```

**Frida 解法**：观察 verify 的入参与 MessageDigest 输入；也可以直接调 `HashSeed.seed()` 看它还原出的口令：

```javascript
// hook_l10.js
Java.perform(function () {
    function b2h(b) { var s=''; for (var i=0;i<b.length;i++){var x=b[i]&0xff; s+=('0'+x.toString(16)).slice(-2);} return s; }
    var MD = Java.use('java.security.MessageDigest');
    MD.update.overload('[B').implementation = function (d) {
        console.log('[digest] 输入 hex:', b2h(d));
        return this.update(d);
    };
    MD.digest.overload('[B').implementation = function (d) {
        console.log('[digest] 输入 hex:', b2h(d));
        return this.digest(d);
    };
    console.log('[seed] 还原结果 =', Java.use('com.fatdog.reverse.HashSeed').seed());
});
```

**答案**：`FLAG_18_L10{sha256_gate_cleared}`（口令即 `HashSeed.seed()` 的还原结果）

---


### 关卡 11：HMAC 验签（Frida 第 2 关）

**考点**：HMAC = 带密钥的哈希；密钥和待验明文都按字节分片异或藏在 `HmacParts`，还原出两份材料才算过关。

**静态解法**：
1. jadx 看 `MsgAuthActivity.verify()`：HMAC 调用 `HmacParts.hmacKey()`，指纹来自 `HmacParts.fingerprint()`。
2. `HmacParts` 里密钥与明文都按 `KA/KB`、`MA/MB` 两组异或数组存放，先还原后拼接。
3. Python 复刻：

```python
import hmac, hashlib
def dec(a, k):
    return bytes(x ^ k for x in a).decode()
key = dec([90,93,72,88,89,81,83,99],0x3C) + dec([84,81,93,95,99,87,89,69],0x3C)
msg = dec([85,82,71],0x33) + dec([54,59,56],0x5A)
print(key, msg)
print(hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest())  # 042d...77c
```

**Frida 解法**：Hook Mac.init/doFinal 观察实际密钥与输入；也可以调 `HmacParts.hmacKey()`、`passPhrase()` 直接看还原结果：

```javascript
// hook_l11.js
Java.perform(function () {
    function b2h(b) { var s=''; for (var i=0;i<b.length;i++){var x=b[i]&0xff; s+=('0'+x.toString(16)).slice(-2);} return s; }
    var HP = Java.use('com.fatdog.reverse.HmacParts');
    console.log('[key] 还原结果 =', HP.hmacKey());
    console.log('[msg] 还原结果 =', HP.passPhrase());
    var Mac = Java.use('javax.crypto.Mac');
    Mac.init.overload('java.security.Key').implementation = function (key) {
        console.log('[mac] init, algorithm =', key.getAlgorithm());
        return this.init(key);
    };
    Mac.doFinal.overload('[B').implementation = function (data) {
        console.log('[mac] 输入 hex:', b2h(data));
        return this.doFinal(data);
    };
});
```

**答案**：`FLAG_18_L11{hmac_sign_passed}`（口令即 `HmacParts.passPhrase()` 的还原结果）

---

### 关卡 12：AES 密码库（Frida 第 3 关）

**考点**：AES-CBC 的密钥/IV/密文三件套；**内容开始分散到工具类**（`SBox`），且开始出现**诱饵类**（`Md5Wrap`、`MiscCrypt` 无人调用）。

**静态解法**：
1. jadx 看 `b1Activity.verify()`，它只调用 `SBox.decryptVault()`；真正的东西在 `SBox`：

```java
static final byte[] KEY = "FATDEMO_KEY_12AB".getBytes();
static final byte[] IV  = "0001020304050607".getBytes();
static final String VAULT = "k3jDkAuOkMyqETJhEnH2heWsp08zaC1xtgRbNRgUurk=";
// 用 Cipher.getInstance("AES/CBC/PKCS5Padding") 解密 VAULT
```

2. Python 解密（需要 `pip install pycryptodome`）：

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = b'FATDEMO_KEY_12AB'
iv  = b'0001020304050607'
data = base64.b64decode('k3jDkAuOkMyqETJhEnH2heWsp08zaC1xtgRbNRgUurk=')
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
        console.log('[cipher] 输入:', b2h(input), '-> 输出:', b2h(r));
        return r;
    };
});
```

**进阶 Frida 训练——构造函数 `$init` hook**：

本关的 `SBox` 类把 KEY 从静态字段改成了**实例字段**，在构造函数里通过 XOR 种子数组计算。这意味着 `new SBox()` 时才产生 KEY，Frida 需要 hook `$init` 才能看到完整的密钥材料：

```javascript
// hook_l12_init.js — 构造函数 hook 训练
Java.perform(function () {
    var SBox = Java.use('com.fatdog.reverse.SBox');
    // hook 构造函数，观察 KEY 的生成过程
    SBox.$init.implementation = function () {
        this.$init();
        // KEY 是实例字段，构造完成后才能读
        console.log('[SBox.$init] key = ' + this.key.value);
    };
    // hook decryptVault，验证实例方法也能拿到 key
    SBox.decryptVault.implementation = function () {
        console.log('[SBox.decryptVault] key = ' + this.key.value);
        return this.decryptVault();
    };
});
```

> **训练点**：`$init` 是 Frida 对构造函数的固定名称。当密钥在构造时生成（而非静态字段），必须 hook `$init` 才能捕获。注意 `this.key.value` 是读取 Java 实例字段的语法——`value` 是 Frida 桥接 Java 字段的固定属性。

**答案**：`FLAG_18_L12{aes_vault_unlocked}`

---


### 关卡 13：双重校验（Frida 第 4 关）

**考点**：**双参数 + 双算法**；一关的内容横跨多个类（`SignUtil` + `KBox`）；用 jadx"Find Usage"排除诱饵（`HashFactory` 无人调用）。

**静态解法**：
1. jadx 看 `k4Activity.verify(account, token)`：`SignUtil.checkAccount(account) && KBox.checkToken(token)`。
2. 账号：`SignUtil` 里账号种子按 `SEED_A/SEED_B` 两段异或存放；`accountSeed()` 还原后和 `fingerprint()`（即 `ACCOUNT_HASH`）对拍：

```python
import hashlib
def dec(a, k):
    return bytes(x ^ k for x in a).decode()
account = dec([82,89,83,82,99], 0x3C) + dec([73,79,89,78], 0x3C)
print(account)  # 需要自己还原
print(hashlib.md5(account.encode()).hexdigest())  # c2fb08b69f270e9aae6e76438ec724a3
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

4. 输入上面还原出的账号和令牌 → 出 flag。

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
        console.log('[aes] 输出:', b2h(r));
        return r;
    };
    console.log('[account] 还原结果 =', Java.use('com.fatdog.reverse.SignUtil').accountSeed());
});
```

**进阶 Frida 训练——`overload` 重载方法选择**：

本关的 `SignUtil.checkAccount` 有两个重载：`checkAccount(String)` 和 `checkAccount(String, String)`（后者是诱饵，固定返回 false）。直接 hook `checkAccount` 会报"multiple matches"错误，必须用 `overload` 指定参数类型：

```javascript
// hook_l13_overload.js — overload 选择训练
Java.perform(function () {
    var SU = Java.use('com.fatdog.reverse.SignUtil');

    // 错误写法（会报错）：
    // SU.checkAccount.implementation = function (a) { ... };
    // Error: checkAccount has more than one overload

    // 正确写法：用 overload 指定参数类型
    SU.checkAccount.overload('java.lang.String').implementation = function (account) {
        var result = this.checkAccount(account);
        console.log('[checkAccount] account=' + account + ' -> ' + result);
        return result;
    };

    // 也可以 hook 诱饵重载，观察它的行为
    SU.checkAccount.overload('java.lang.String', 'java.lang.String').implementation = function (a, b) {
        console.log('[checkAccount decoy] a=' + a + ', b=' + b + ' -> false');
        return false;
    };
});
```

> **训练点**：Java 方法重载（overload）在 Frida 里必须用 `.overload('参数类型')` 显式选择。类型是完整类名：`'java.lang.String'`、`'[B'`（byte 数组）、`'int'` 等。不指定 overload 是 Frida 新手最常见的报错之一。

**答案**：`FLAG_18_L13{dual_param_dual_alg}`

---


### 关卡 14：三层链路（Frida 第 5 关，最难）

**考点**：**一条输入链过三次变换**（base64 + AES×2 + XOR）；两把密钥分散在两个工具类；**大量诱饵类**（`AesKit`、`Md5Tools`、`KeyFactory`——尤其 KeyFactory 里有一把假密钥，别上当）；正确使用 jadx 交叉引用定位真实链路。

**静态解法**：
1. jadx 看 `z9Activity.verify(license, deviceId)`：

```java
byte[] s1 = XBox.decryptA(license);          // 第 1 层：base64 + AES-ECB(密钥A在XBox)
String plain = Mux.finish(s1);               // 第 2、3 层：AES-ECB(密钥B在Mux) + 逐字节异或 0x5A
return "GRANTED_2026_OK!".equals(plain)
        && md5Hex(deviceId).equals(PivotParts.fingerprint());
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

4. deviceId：`PivotParts` 里 `DEV_A/DEV_B` 分别 `^0x3C`、`^0x5A`，还原后再用 MD5 指纹对拍：

```python
import hashlib
def dec(a, k):
    return bytes(x ^ k for x in a).decode()
device = dec([76,85,74,83,72,99], 0x3C) + dec([62,63,44,51,57,63], 0x5A)
print(device)  # 需要自己还原
print(hashlib.md5(device.encode()).hexdigest())  # a94f8d335f87849687b77fb244a1d6f4
```
5. 输入还原出的 license 和 deviceId → 出 flag。

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
    console.log('[device] 还原结果 =', Java.use('com.fatdog.reverse.PivotParts').deviceId());
});
```

**flag**：`FLAG_18_L14{triple_layer_chain}`

---


## 网络对抗（L15-19）

### 网络关通用配置与 Charles 对应表

证书规则先说清楚：`8787` 是纯 HTTP，不需要 CA；`8443` 与 `8444` 才走 TLS。`8443` 的多数客户端把 `certs/ca.crt` 编进 App，只信这张 CA 签发的证书；`8444` 在同样信任链上额外要求客户端出示 `certs/client.p12`（口令 `fatdemo_mt26`）。这些证书必须与当前 APK 内嵌证书同源，重跑 `gen_certs.py` 后要重编 APK。

还有一个关键区别：APK 里拿到的是 CA **公钥**，不是 CA 私钥。只分析 APK 可以还原 `certs/ca.crt`，但不能拿它去让 Charles 签发新叶证书；要配置 Charles Root Certificate，需要使用服务端仓库里配套的 `certs/ca.key`。如果练习条件只有 APK，就应改走 Frida：绕过自定义 TrustManager，有 pin 的关卡再做换 pin 或 pin 校验绕过。

> **题解主次必须分清**：`L21-L27` 的主线是 Frida Hook/绕过 App 内的 TLS 校验。把仓库自带的 `ca.crt + ca.key` 导入 Charles 后直接抓包，只因为当前是开卷靶场才成立，属于捷径；真实场景没有服务端 CA 私钥，不能把它写成标准答案。下面的“Charles 配置”主要告诉你怎么搭抓包环境，具体绕校验以各关的“题解主线”为准。`L26` 是例外：必须提取并使用 APK 内的客户端证书完成 mTLS。

直连模式（不抓包）：模拟器直接访问 `10.0.2.2`；真机通过 `adb reverse tcp:8787 tcp:8787`、`adb reverse tcp:8443 tcp:8443`、`adb reverse tcp:8444 tcp:8444` 映射到本地服务端。

Charles 抓包模式使用 Reverse Proxies，端口要错开，否则会与本地服务端抢占同一监听端口：

| App 请求 | `adb reverse` | Charles 本地监听 | Charles 上游 |
|---|---:|---:|---|
| `8787` HTTP | `tcp:8787 tcp:18787` | `18787` | `127.0.0.1:8787` |
| `8443` HTTPS | `tcp:8443 tcp:18443` | `18443` | `127.0.0.1:8443` |
| `8444` mTLS | `tcp:8444 tcp:18444` | `18444` | `127.0.0.1:8444` |

在 `Proxy -> Reverse Proxies` 建立三条映射并启用。下面这段 Root Certificate 配置只是在演示本仓库的**开卷捷径**：`Proxy -> SSL Proxying Settings -> Root Certificate` 导入 `certs/ca.crt` / `certs/ca.key`，再允许 `127.0.0.1:8443`、`127.0.0.1:8444`。只给手机安装 Charles 自己的 CA 不够：自定义 `TrustManager` 不读系统信任库，Charles 必须直接用项目 CA 给 `127.0.0.1` 签发叶证书。L26 还要在 `Client Certificates` 为 `127.0.0.1:8444` 导入 `certs/client.p12`，密码 `fatdemo_mt26`，并启用该客户端证书。

切换直连与抓包模式前先清掉同名映射：`adb reverse --remove tcp:8787`、`adb reverse --remove tcp:8443`、`adb reverse --remove tcp:8444`，否则旧映射会继续把流量直接送回本地服务端。

逐关的抓包配置如下：

| 关卡 | 题解主线 | 开卷捷径 / Charles 配置 |
|---|---|---|
| `L15-L19` | HTTP 协议与签名复刻 | 不需要 CA；只需 `18787 -> 127.0.0.1:8787` |
| `L21` | Frida Hook `SSLContext.init` / `TrustManager` | 导入项目 CA 的 `ca.crt + ca.key`，让 Charles 直接签发叶证书 |
| `L22` | Frida Hook TrustManager + `CertificatePinner.check` | 项目 CA 只能过信任闸；静态 Python 也不经过 App pin |
| `L23` | Frida Hook `onReceivedSslError` 并 `handler.proceed()` | 项目 CA 不是本关题解；`curl -k` 只能算静态抄近道 |
| `L24` | 保留真实校验链，Hook `Z24Core.realPin` 换 pin | 静态 Python 带 CA 直接取数是开卷捷径 |
| `L25` | Frida 原生层复用/Hook `nativeSign` | 静态提取密钥并带 CA 复刻是开卷捷径 |
| `L26` | 提取 `mt_client.p12`，配置客户端证书完成 mTLS | CA 只验服务端；还需 `Client Certificates` 绑定 `127.0.0.1:8444` |
| `L27` | Frida 放倒 pin，或换 pin 后继续跟踪签名链 | 静态解出三把密钥并带 CA 复刻是开卷捷径 |

`L28-L53`、`KL6-KL10`、`KL30`、`KKL2-KKL5` 中凡使用 `8443` 的请求，也复用同一套反向代理和项目 CA。若对应关卡还有 pin、守卫或 native 校验，以该关卡正文为准。


### 关卡 15：千数求和（网络关，数据只能发包拿）

**考点**：请求参数里的签名（HMAC-SHA256）；**数据只在服务端、APK 里没有**——这是 Frida/签名逆向的完整闭环：先用 Frida 观察 App 发包瞬间怎么算签名，再复刻签名取数。

**环境**：先启动本地模拟服务端：

```
python server.py           # HTTP 8787 / HTTPS 8443 / mTLS 8444
```

App 端地址由 `NetHost` 自动切换：模拟器走 `http://10.0.2.2:8787`（宿主机回环），真机走 `http://127.0.0.1:8787`（需 `adb reverse tcp:8787 tcp:8787`），无需改 config.json。

Charles 抓包时不要再用上面的同名端口直连，改用 `adb reverse tcp:8787 tcp:18787`，具体拓扑见本节开头的“网络关通用配置与 Charles 对应表”。

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

**进阶 Frida 训练——内部类 `$` hook**：

本关的 `Sg` 类有一个静态内部类 `Sg$KeyBuilder`，密钥碎片的拼接逻辑藏在里面。Frida hook 内部类需要用 `$` 语法引用：

```javascript
// hook_l15_inner.js — 内部类 hook 训练
Java.perform(function () {
    // 内部类用 外部类$内部类 名引用
    var KeyBuilder = Java.use('com.fatdog.reverse.Sg$KeyBuilder');
    KeyBuilder.build.implementation = function () {
        var key = this.build();
        console.log('[Sg$KeyBuilder.build] key = ' + key);
        return key;
    };

    // 对比：hook 外部类的 buildKey，看差异
    Java.use('com.fatdog.reverse.Sg').buildKey.implementation = function () {
        var k = this.buildKey();
        console.log('[Sg.buildKey] key = ' + k);
        return k;
    };
});
```

> **训练点**：Java 静态内部类在 dex 里用 `外部类$内部类` 命名。Frida 用 `Java.use('com.fatdog.reverse.Sg$KeyBuilder')` 引用。匿名内部类也一样：`Sg$1`、`Sg$2` 等。这是 hook 回调、listener、匿名实现类的基础。

**答案**：加和 `49580`；flag `FLAG_18_L15{thousand_number_sum}`

---


### 关卡 16：流密码暗河（RC4 + MD5，请求响应都加密）

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
// 在 App 里点"请求该页"，控制台自动打出 reqKey/rspKey 和加解密前后的数据
```

**进阶 Frida 训练——内部类 `$` 语法（进阶）**：

本关的 `Rc4Core` 有一个静态内部类 `Rc4Core$KeyMaterial`，存放密钥提示信息。与 L15 的 `Sg$KeyBuilder` 不同，这个内部类的方法返回的是 hint 而非实际密钥，训练学生区分"观察内部类"和"提取实际密钥"：

```javascript
// hook_l16_inner.js — 内部类进阶训练
Java.perform(function () {
    // hook 内部类，观察它提供的信息
    var KM = Java.use('com.fatdog.reverse.Rc4Core$KeyMaterial');
    KM.hint.implementation = function () {
        var h = this.hint();
        console.log('[Rc4Core$KeyMaterial.hint] ' + h);
        return h;
    };

    // 对比：hook 外部类的 crypt 方法，观察实际加解密
    var RC4 = Java.use('com.fatdog.reverse.Rc4Core');
    RC4.crypt.implementation = function (data, key) {
        var out = this.crypt(data, key);
        console.log('[Rc4Core.crypt] key=' + key.length + ' bytes, data=' + data.length + ' -> ' + out.length + ' bytes');
        return out;
    };
});
```

> **训练点**：内部类不一定是核心逻辑，可能是辅助信息。Frida 可以 hook 任何类的任何方法，但关键是要判断哪些是真钥匙、哪些是提示牌。L15 的 `Sg$KeyBuilder` 直接返回密钥，L16 的 `Rc4Core$KeyMaterial` 只返回 hint——逆向时需要根据上下文判断价值。

**答案**：加和 `24074`；flag `FLAG_18_L16{rc4_stream_encrypted}`

---


### 关卡 17：玄门遁甲（国密 SM4 + SM3 表单）

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


### 关卡 18：乾坤密钥（RSA 加密参数 + DES 解密响应）

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


### 关卡 19：雾里看花（AES + HMAC，加密包被真 R8 混淆）

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


## SSL 抓包（L21-27）


### 关卡 21：踏云寻踪（HTTPS + 自定义 TrustManager）

**考点**：服务端升级 HTTPS（自签 CA）。App 的 OkHttp 客户端装了一个**自定义 TrustManager**，只信内置的自签 CA——代理工具（mitmproxy/Fiddler/Charles）换发的证书不是这个 CA 签的，握手直接失败。这就是教程 21 的第一道闸：抓包先被信任校验挡住。

**类在哪**：`w1Activity` → `Tm.fetchPage`。CA 证书的 DER 字节藏在 `Tm.CAA`（异或 0x5A）；HMAC 密钥一半在 `Km`（`fatdemo_`）、一半在 `Tm.TB`（`ssl_hmac`）。诱饵 `CertBox`。

**Charles 配置**：使用 `18443 -> 127.0.0.1:8443`。把 `certs/ca.crt` / `certs/ca.key` 导入 Charles 的 Root Certificate 属于**开卷捷径**；题解主线是下面的 Frida TrustManager 绕过。

**先读懂流程**：

```text
sign = HMAC-SHA256("fatdemo_ssl_hmac", "page=N&ts=T")
GET https://…:8443/api/tls?page=N&ts=T&sign=…
响应 {"page":N,"nums":[…]}        ← 明文！这关的难点全在 TLS 握手，不在加解密
```

> 题解主线是路线 3（Hook TrustManager）；路线 1、2 都是利用仓库提供了项目 CA 私钥的开卷捷径。

**路线 1：带项目 CA 静态复刻（开卷捷径）**。项目 `certs/ca.crt` 就是 App 内置的那张自签 CA。Python 用它当信任锚，直接复刻签名取数；这条路线不经过 App 的 TrustManager，所以不能代替 Hook 训练：

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

**路线 2：带项目 CA 抓包（开卷捷径）**。把与 APK 匹配的 `certs/ca.crt` / `certs/ca.key` 交给 Charles/Fiddler/mitmproxy 当 Root Certificate，代理签发的叶证书会通过 App 的自定义 TrustManager。该路线依赖仓库直接给出了 CA 私钥，真实场景通常不成立。

**路线 3：Frida 拆信任校验（题解主线，推荐）**。经典做法是把所有 `SSLContext.init` 传入的 TrustManager 换成什么都不检查的假货，让 App 继续走真实业务逻辑：

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


### 关卡 22：双锁封疆（TrustManager + CertificatePinner 双闸门）

**考点**：在 L21 的自定义信任之上再叠一层 OkHttp `CertificatePinner`：把服务器证书的 **SPKI（公钥指纹）**焊死成 `sha256/Tix1…`，还加了个只认 `10.0.2.2/127.0.0.1/localhost` 的 HostnameVerifier。就算 Hook 掉 TrustManager 让代理证书被信任，pinner 发现证书指纹换了照样炸——**两道闸都要过**。

**类在哪**：`x2Activity` → `Pn.fetchPage`。`Pn.PIN` 就是 SPKI 指纹（明文字符串，可以直接看到）；HMAC 密钥 `Kp`（`fatdemo_`）+ `Pn.KB`（`pin_key`）。CA 复用 `Tm.caDer()`。诱饵 `Pim`。

**Charles 配置**：同样使用 `18443`。导入项目 CA 只能解决第一道 TrustManager，属于环境捷径；Charles 叶证书的 SPKI 与原服务端证书不同，题解主线仍要 Hook `CertificatePinner.check`。

**先读懂流程**：和 L21 一样，端点换成 `GET https://…:8443/api/pin`，密钥换 `fatdemo_pin_key`，响应明文 JSON。

**路线 1：带项目 CA 静态复刻（开卷捷径；题解主线见路线 2）**。pinner 只影响 OkHttp 客户端，用 Python 带 `certs/ca.crt` 取数不会经过它；这条路线绕开了关卡重点：

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

**路线 2：Frida 拆双闸门（题解主线，推荐）**。第一道同 L21（换掉 TrustManager），第二道 Hook `okhttp3.CertificatePinner.check` 让它空跑：

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


### 关卡 23：白屏迷雾（WebView 自签证书错误）

**考点**：WebView 加载 HTTPS H5 页，证书自签、不在系统信任库 → `WebViewClient.onReceivedSslError` 被回调。App 在这里调 `handler.cancel()`——**页面白屏**。破解 = Hook 这个方法，改成调 `handler.proceed()` 放行。这是教程 21 的 WebView 分支，也是真实 App 里最常见的证书错误处理点。

**类在哪**：`y3Activity` + 具名内部类 `WvClient`；页面路径 `/h5/v23` 在 `Hq` 里异或 0x2F 藏着（主机由 `NetHost` 自动选）。诱饵 `WvKit`。**flag 不在 APK**，在服务端 H5 页面的 `<span id="flag">` 里。

**Charles 配置**：`18443 -> 127.0.0.1:8443` 可以看到请求，但 WebView 走系统信任校验，项目 CA 不会自动替代本关的 `handler.cancel()` 逻辑。要在 App 内通过，仍按下面的 Frida 方案调用 `handler.proceed()`。

**先读懂流程**：

```text
web.loadUrl("https://…:8443/h5/v23")            # 仅 HTTPS，HTTP 访问 403
→ onReceivedSslError(...) { handler.cancel(); }  # 白屏
→ （Hook 放行后）onPageFinished → evaluateJavascript 读 #flag → 庆祝 + 通关打点
```

**路线 1：静态抄近道（开卷捷径）**。电脑上无视证书错误直接看页面（`-k` 就等价于"proceed"），不涉及 App 的 SSL 错误回调：

```bash
python server.py
curl -k https://127.0.0.1:8443/h5/v23     # 页面里 #flag 就是答案
```

**路线 2：Frida 正解（题解主线，推荐）**。Hook `com.fatdog.reverse.y3Activity$WvClient.onReceivedSslError`，把 `cancel` 换成 `proceed`：

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

**补充：原理页**。`SslErrorHandler` 只有两个选择：`proceed()`（无视错误继续加载）和 `cancel()`（终止加载）。真实 App 常在这里做白名单（只对自己域名 proceed），所以逆向时要重点看它判断域名的那段逻辑——哪些域名被放行、哪些被砍掉。

**答案**：flag `FLAG_18_L23{webview_ssl_error}`（这关没有求和要求，flag 只在服务端页面里）

---


### 关卡 24：换票迷局（反 Hook 检测 + 内存换 pin）

**考点**：pin 校验函数带"完整性守卫"——直接把校验 Hook 掉放行会被守卫抓住；正解是定位 pin 常量，用 Frida 把内置 pin 动态换成 mitmproxy 证书的 pin（**内存换票**）。这是教程 21 的"第 3 层最隐蔽打法"。

**类在哪**：

- `z24Activity`：关卡页（100 页 × 每页 10 个，分页取回求和）。
- `Aw`：OkHttp 客户端。自定义 TrustManager 只信内置 CA（复用 `Tm.caDer()`，所以 mitmproxy 证书先过不了第一关）；`HostnameVerifier.verify` 在这里算服务器证书 SPKI 并交给 pin 校验。
- `Z24Core`：pin 常量（XOR `^0x5A` 数组，无明文）+ `checkPin`/`assertGuard` 反 Hook 守卫。
- `Tk`：HMAC 密钥前半段 `fatdemo_`；`Aw.KB` 是后半段 `swap_key`，拼出 `fatdemo_swap_key`。
- 诱饵 `Gp`：一个"假 pin + 假放行"的工具类，没有任何人调用它——最先翻到它的人最容易掉坑。

**Charles 配置**：使用 `18443`。导入项目 CA 只是解决信任链的开卷捷径；题解主线是保留真实校验路径，Hook `Z24Core.realPin`，返回抓包代理为 `127.0.0.1` 签发叶证书的 SPKI pin。

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

**路线 1：带项目 CA 静态复刻（开卷捷径；题解主线见路线 2）**。pin 只保护 App 的 OkHttp 客户端，用 Python 带 `certs/ca.crt` 取数不会经过它，因此会跳过 guard 与换 pin 训练：

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

**路线 2：Frida script E——内存换票（题解主线，推荐）**：

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

**进阶 Frida 训练——内部类 `$` 提取隐藏常量**：

本关的 `Z24Core` 有一个静态内部类 `Z24Core$PinVault`，存放实际的 pin 常量（XOR `^0x5A` 数组运行时还原）。Frida 可以直接调用内部类的静态方法拿到 pin，无需手工逆向 XOR 数组：

```javascript
// hook_l24_pinvault.js — 内部类常量提取训练
Java.perform(function () {
    // 直接调内部类的 decode 方法，拿到真实 pin
    var PinVault = Java.use('com.fatdog.reverse.Z24Core$PinVault');
    var pin = PinVault.decode();
    console.log('[Z24Core$PinVault.decode] realPin = ' + pin);

    // 也可以 hook realPin()，看它是否委托给 PinVault
    var Z24 = Java.use('com.fatdog.reverse.Z24Core');
    Z24.realPin.implementation = function () {
        var p = this.realPin();
        console.log('[Z24Core.realPin] ' + p);
        return p;
    };
});
```

> **训练点**：`decode()` 是 static 方法，可以直接 `PinVault.decode()` 调用，不需要实例。这比 L15/L16 的内部类更进一步——展示了如何用 Frida 从内部类中**提取隐藏常量**。配合 L24 的"内存换票"场景，学生可以先用这个脚本拿到 pin，再决定是静态复刻还是内存替换。

**答案**：加和 `50225`；flag `FLAG_18_L24{anti_hook_pin_swap}`

---


### 关卡 25：灵台证真（JNI native 校验，教程 22 预告）

**考点**：这一关把"门禁 + 签名"整段搬进了 `libnative.so`。jadx 里只有两行 `native` 声明，Java 层 Hook 什么都拿不到——签名根本不经过 Java。这是教程 22（native 逆向）的入门预告，所以难度刻意压低：**密钥没加密，strings 就能看到**。

**类在哪**：

- `a25Activity`：关卡页（100 页 × 每页 10 个，分页取回求和）。
- `Nx`：JNI 桥。`System.loadLibrary("native")` + 两个声明：`verifyServer(String)`、`nativeSign(int, long)`。
- `By`：OkHttp 客户端，调 `Nx` 两个方法后发 `GET /api/native`。
- `Rj`：诱饵（假密钥 `fatdemo_fake_key_java`，没人调用）。
- 真身：APK 里的 `lib/arm64-v8a/libnative.so`、`lib/armeabi-v7a/libnative.so`（源码 `app/jni/native.c`）。

**Charles 配置**：使用 `18443 -> 127.0.0.1:8443`。把项目 CA 交给 Charles 属于开卷捷径；本关题解主线是在 native 层观察或复用 `nativeSign`，而不是只靠服务端 CA 绕过。

**先读懂流程**：

```text
loadPage → By.fetchPage
  → Nx.verifyServer(host)     # C：白名单 10.0.2.2 / 127.0.0.1 / localhost
  → Nx.nativeSign(page, ts)   # C：HMAC-SHA256("fatdemo_jni_2026", "page=N&ts=T") 十六进制
  → OkHttp GET https://…:8443/api/native?page=N&ts=T&sign=...（自定义信任，内置 CA）
```

**为什么 Java Hook 无效**：`Mac`/`MessageDigest` 的 Hook 一个都不会触发（HMAC 在 C 里实现）；jadx 里也没有密钥。要动它，要么静态读 so，要么 Frida 上原生层。

**路线 1：静态提取 + Python 复刻（开卷捷径；题解主线见路线 2）**。APK 就是个 zip：

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

**路线 2：Frida 原生层（题解主线，推荐）**。Java 层不管用，就上 `Interceptor` / `NativeFunction`：

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

拿到签名后，和路线 1 一样拼 URL 取满 100 页。

**路线 3：改返回值 / patch so**。`Interceptor.attach(verifyServer)` 的 `onLeave` 里 `retval.replace(1)` 可以放行白名单外的主机（比如把 config.json 指到局域网 IP 时用）；直接把 so 里的白名单字符串 patch 掉也一样。真机上改 so 记得重打包重签名。

**防坑提醒**：

- `Rj.FAKE_KEY` 是诱饵，用它算签名必 403。
- Hook `Mac.doFinal` / `MessageDigest.update` 白搭：本关 HMAC 在 C 里，Java 根本没有这些调用。
- `verifyServer` 只认 10.0.2.2 / 127.0.0.1 / localhost：把 config.json 指到别的 IP 会先被门禁拦住。
- 自校验向量：`HMAC(fatdemo_jni_2026, "page=1&ts=123")` = `92bf819c0e889a884493c891b6701334032762a1d2309b1795bd555f682bf712`——自己复刻完先拿它对比。

**答案**：加和 `52674`；flag `FLAG_18_L25{native_jni_verify}`

**进阶 Frida 训练——`CpuContext` 寄存器读写**：

本关的 `Interceptor.attach` 解法里，`onLeave` 用 `env.getStringUtfChars(retval)` 读返回值。另一种更底层的方式是直接读 ARM64 寄存器 `x0`——native 函数的返回值就在 x0 里：

```javascript
// hook_l25_ctx.js — CpuContext 寄存器训练
Java.perform(function () {
    var addr = Module.findExportByName('libnative.so', 'Java_com_fatdog_reverse_Nx_nativeSign');
    Interceptor.attach(addr, {
        onEnter: function (args) {
            // args 是 JNI 指针数组：JNIEnv*, jobject, jint page, jlong ts
            console.log('[nativeSign] page=' + args[2].toInt32() + ' ts=' + args[3].toString(10));
        },
        onLeave: function (retval) {
            // 方式 A：通过 JNI env 读（现有写法）
            var env = Java.vm.getEnv();
            var viaEnv = env.getStringUtfChars(retval, ptr(0)).readCString();

            // 方式 B：直接读 x0 寄存器（CpuContext）
            // ARM64 调用约定：x0 存放返回值（指针类型）
            var viaX0 = context.x0.readUtf8String();

            console.log('[retval] env=' + viaEnv);
            console.log('[x0]    x0=' + viaX0);
            // 两者应该一致：都是 nativeSign 返回的 jstring 指针
        }
    });
});
```

> **训练点**：`context` 对象暴露了 CPU 寄存器（ARM64: x0-x30, sp, pc; ARM: r0-r12, sp, lr, pc）。`onEnter` 时可读参数寄存器，`onLeave` 时可读/改返回值寄存器。`retval.replace()` 本质就是改 x0。比 `env.getStringUtfChars` 更底层，适用于 JNI env 不可用或需要读中间状态的场景。

---


### 关卡 26：双符合璧（双向 TLS / mTLS，客户端证书）

**题面**：这一关服务端在 **TLS 握手层强制验证客户端证书**（双向 TLS / mTLS）。App 不光要验服务端（内置 CA），还要**出示自己的客户端证书+私钥**——少一张，握手直接失败。抓包工具没这证书，连明文都看不到；想复刻取数，得先把 APK 里的证书"抠"出来。

**考点**：客户端证书提取、PKCS12、mTLS 原理。

**涉及类**：

- `b26Activity`：关卡页（100 页 × 每页 10 个，分页取数求和）。
- `Vd`：OkHttp 客户端。信任侧沿用内置 CA（`Tm.caDer()`）；出示侧用 `Mc.loadP12()` 产出 KeyManager，握手时自动出示客户端证书链。端点 `https://…:8444/api/mtls`。
- `Zt`：HMAC 密钥前半段（^0x3C）**兼** PKCS12 密码前半段（^0x37）。
- `Mc`：PKCS12 保险库。密码后半段（^0x5B）在本类，运行时拼出完整密码打开 `assets/mt_client.p12`。
- `MtlsKit`：**诱饵**（假密码 `client_secret_26`、假别名，无人调用）。
- 服务端：`:8444` 独立 app 实例 + `ssl_cert_reqs=CERT_REQUIRED`（信任 `certs/ca.crt` 签发的客户端证书）。注意 `/api/mtls` **不在** 8787/8443 上——想不带证书从老端口绕过是死路（404）。

**Charles 配置**：使用 `18444 -> 127.0.0.1:8444`。`L26` 是 SSL 组里的例外：不能靠 Hook HTTP 层代替客户端证书。题解主线是从 APK 提取 `assets/mt_client.p12` 和密码，再到 Charles 的 `Client Certificates` 中给 `127.0.0.1:8444` 绑定该证书；Root Certificate 仍用项目 CA 只负责验证服务端。

**调用链路**：

```text
loadPage → Vd.fetchPage
  ├─ Mc.buildPassword() = Zt.pxa()(^0x37) + decodePXB()(^0x5B)   # "fatdemo_" + "mt26"
  ├─ KeyStore("PKCS12").load(assets/mt_client.p12, password)      # 别名 fatdog-client
  ├─ SSLContext.init(KeyManagers, TrustManagers(Tm.caDer()), …)   # 双向都齐了
  └─ GET https://…:8444/api/mtls?page=N&ts=T&sign=HMAC-SHA256(Zt.pa()+Vd.kb(), "page=N&ts=T")
```

**路线 1：静态提取 + Python 复刻（题解主线，推荐）**：

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

**路线 2：Frida 动态拿密码 / 抓包**：

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


### 关卡 27：万法归宗（抓包→复刻全闭环）

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

**Charles 配置**：使用 `18443`。导入项目 CA 属于开卷捷径，而且只能解决信任闸；内置 SPKI pin 仍会让 Charles 叶证书失配，题解主线是按本关 Frida 方案处理 pin。

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

**路线 1：静态还原 + Python 复刻（开卷捷径；题解主线见路线 2）**：

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

**路线 2：Frida 放倒双闸门抓包（题解主线，推荐）**：

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

**为什么叫万法归宗**：这关串起了入门到进阶的全套技能——搜入口 → 认混淆 → 解 XOR → 绕 pinning → 复刻签名链。四步少一步都拿不到 50623。



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
| 28 | `FLAG_18_L28{runtime_decoded_key}`（加和 `49750`） |
| 29 | `FLAG_18_L29{register_natives_caught}`（加和 `50208`） |
| 30 | `FLAG_18_L30{nameless_dispatch}`（加和 `51127`） |
| 31 | `FLAG_18_L31{cross_layer_key}`（加和 `50768`） |
| 32 | `FLAG_18_L32{silent_poison_defused}`（加和 `51745`） |
| 33 | `FLAG_18_L33{crc_guard_bypassed}`（加和 `49502`） |
| 34 | `FLAG_18_L34{guixu_all_in_one}`（加和 `49932`） |
| 35 | `FLAG_18_L35{sbox_tells_all}`（加和 `51217`） |
| 36 | `FLAG_18_L36{base64_is_not_encryption}`（加和 `49495`） |
| 37 | `FLAG_18_L37{avalanche_hides_the_blood}`（加和 `51242`） |
| 38 | `FLAG_18_L38{puppet_line_attached}`（Hook XpGate.check 即通） |
| 39 | `FLAG_18_L39{swap_the_argument}`（deviceId = fatdog_xp_2026） |
| 40 | `FLAG_18_L40{secret_field_exposed}`（私钥 = Fatdog_xp40_secret） |
| 41 | `FLAG_18_L41{triple_gate_broken}`（替换 checkB 即通） |
| 42 | `FLAG_18_L42{persistence_is_power}`（自毁重启 Hook 仍在） |

> 关卡 9 的 else 分支里那个 `FLAG_18_L9{single_gate_not_enough}` 是诱饵，不是有效 flag。


---


## Native 试炼（L28-37）


### 关卡 28：缄默之钥（native 字符串加密）

**考点**：密钥 `Fatdog_unhappy` 被 ^0x5C 存成字节数组 `KEY28_KX` 躺在 libaxol.so 的 .rodata，运行时才解到栈缓冲喂 HMAC-SHA256。strings 只能看到诱饵 `Fatdog_silent`（Java 层 `Fk.FAKE_KEY` 与 so 内 `KEY28_DECOY` 双份埋伏）。

**静态路线**
1. 解包 APK 取 `lib/arm64-v8a/libaxol.so`；`strings libaxol.so | grep Fatdog` 只见诱饵。
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
  var addr = Module.findExportByName('libaxol.so', 'Java_com_fatdog_reverse_Zk_nativeSign');
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
      onLeave: function () { if (this.n && this.n.indexOf('libaxol.so') >= 0) hookSign(); }
    });
  });
});
// 另一条路：运行时内存里搜解出来的明文密钥
// var m = Process.findModuleByName('libaxol.so');
// Memory.scanSync(m.base, m.size, '46 61 74 64 6f 67 5f 75 6e 68 61 70 70 79')  // "Fatdog_unhappy"
```

**坑位提醒**：`Fk.FAKE_KEY` 和 so 里明文可见的 `Fatdog_silent` 都是诱饵，拿来算签名只会收到 403。

---


### 关卡 29：隐姓埋名（native 动态注册）

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
// var mod = Process.findModuleByName('libfern.so');
// Interceptor.attach(mod.base.add(偏移), { onEnter/onLeave 见关卡 28 脚本 })
```

拿到三联单里的签名后与本地试算对拍，确认消息格式 `page=N&ts=T`。

**静态路线**

IDA 从 `JNI_OnLoad` 入手：`FindClass("com/fatdog/reverse/Wq")` 后的 `RegisterNatives(env, cls, methods, 1)`，methods 数组第三格就是无名真身地址；顺带看到 `.data` 里的 `KEY29_KX`（12 字节，逐字节 ^0x69 还原 `Fatdog_angry`）。复刻脚本与关卡 28 相同，只换 KEY 为 `b"Fatdog_angry"`、端点为 `/api/l29`，100 页求和 = **50208**。


---


### 关卡 30：无名剑冢（指针表派发 + UTF-16 藏钥）

**考点**：libmica.so 导出表只有一个入口 `Java_com_fatdog_reverse_Vn_nativeSign`，内部经 `K30_TABLE[4]` 派发到四个 noinline 同形签名函数（gloomy/pale/sour/mute），真身沉在文件底部；四把密钥全以 UTF-16LE 码元数组存放——默认 `strings` 与 IDA 字符串窗口均不显示。谁是真身只能靠服务器裁决：错候选的签名同样是一串合法 hex，但换来 403。

**第一步：让藏起来的字符串现形**

```text
strings -el libmica.so        # -el 按 16 位小端扫描：Fatdog_gloomy / pale / sour / mute 全部现形
```

IDA/Ghidra 路线：从唯一导出入口看到一次间接调用 → 找到 `.data` 里的 `K30_TABLE`（四个函数指针）→ 数据窗把那四个码元数组按 16 位字符查看，直接读出明文。

**第二步：确认真身槽位**

静态读派发逻辑（`K30_SLOT=0` → 槽 0 = gloomy）；或动态按偏移逐个 Hook 四个函数看返回值：

```javascript
var mod = Process.findModuleByName('libmica.so');
// IDA 里查得四个函数的模块内偏移后逐一 attach，
// onLeave 用 env.getStringUtfChars 读 jstring 返回值，喂服务器验真（错候选 403）
```

**第三步：Python 复刻取数**（先 `python server.py`）

```python
import time, hmac, hashlib, requests

KEY  = b"Fatdog_gloomy"                 # 槽 0 的真钥匙
BASE = "https://127.0.0.1:8443"         # 模拟器换 https://10.0.2.2:8443

total = 0
for page in range(1, 101):
    ts   = int(time.time())
    sign = hmac.new(KEY, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()
    r = requests.get(f"{BASE}/api/l30", params={"page": page, "ts": ts, "sign": sign},
                     verify="certs/ca.crt", timeout=10)
    total += sum(r.json()["nums"])
print("总和:", total)                    # 51127
```

对拍样例：`HMAC(Fatdog_gloomy, "page=1&ts=1787013761") = bb55d7beb95497d2c541d18d6607c1788ce0a57261dbe9d6ba5e44bfe7b173c5`。

**坑位提醒**：`Xk.FAKE_KEY = Fatdog_mute` 正是槽 3 的假钥匙——Java 层搜到的"密钥"十有八九是它。

**进阶 Frida 训练——`NativePointer` 类型化读取（UTF-16LE 藏钥）**：

本关的密钥以 UTF-16LE 码元数组藏在 `.rodata` 里，`strings` 默认看不到。Frida 可以直接从内存中读取这些字节，无需 IDA：

```javascript
// hook_l30_read.js — NativePointer 类型化读取训练
Java.perform(function () {
    var mod = Process.findModuleByName('libmica.so');

    // UTF-16LE 码元数组在 .rodata 中的布局（IDA 里看到的偏移）
    // 每个字符占 2 字节（小端），例如 'F'=0x0046 存为 46 00
    // 这里用 Memory.scanSync 搜索已知的 UTF-16 特征

    // 方法 A：直接按偏移读（需要 IDA 先查偏移）
    // var keyAddr = mod.base.add(0x1234);  // 偏移需从 IDA 获取
    // var bytes = keyAddr.readByteArray(28);  // 14 字符 × 2 字节
    // console.log('[raw bytes]', hexdump(bytes));

    // 方法 B：搜索内存中的 UTF-16 模式（无需知道偏移）
    // "Fatdog_gloomy" 的 UTF-16LE 字节：46 00 61 00 74 00 64 00 ...
    var pattern = '46 00 61 00 74 00 64 00 6f 00 67 00 5f 00';  // "Fatdog_" UTF-16LE
    var ranges = mod.enumerateRanges('r--');
    for (var i = 0; i < ranges.length; i++) {
        var hits = Memory.scanSync(ranges[i].base, ranges[i].size, pattern);
        for (var j = 0; j < hits.length; j++) {
            // 从匹配位置读 28 字节（14 字符 × 2），解码 UTF-16LE
            var raw = hits[j].address.readByteArray(28);
            var arr = new Uint8Array(raw);
            var s = '';
            for (var k = 0; k < arr.length; k += 2) {
                s += String.fromCharCode(arr[k] | (arr[k+1] << 8));
            }
            console.log('[UTF-16LE key] ' + s);  // Fatdog_gloomy
        }
    }
});
```

> **训练点**：`readByteArray(n)` 从 NativePointer 读 n 字节返回 ArrayBuffer；`Memory.scanSync` 在内存区域中搜索字节模式。UTF-16LE 编码的字符串在内存中每字符占 2 字节（小端序），`strings` 默认按 ASCII 扫描会漏掉。这个技巧适用于所有"UTF-16 藏钥"的关卡（L30、L32、L34、L35 等）。

---


### 关卡 31：两界穿针（跨层密钥 + 干扰包）

**考点**：完整密钥任何单侧都不存在——前半 `Fatdog_` 藏在被 R8 改名的 q 包类里（int[] 码点表 {0x46,0x61,0x74,0x64,0x6f,0x67,0x5f}），后半 `lonely` 是 libquill.so 里的 UTF-16 码元数组；Java 启动时把 Ke.class 递给 native 缓存成全局引用，之后每次签名/加密 native 都回调 `partA()` 取件拼装。请求是 POST 表单 `page/ts/enc/sign`：`enc=hex(RC4(key,"page=N&ts=T"))`、`sign=HMAC-SHA256(key,enc)`。且每页连发 4 个同形包：真包 / 错位包 / 废签包 / 噪声包——假包要么 403 要么返回 `nums:[]`。

**识别干扰包**（抓包或 hook OkHttp 响应）：

| 包 | 特征 | 服务端反应 |
|---|---|---|
| 真包 | 页号/载荷/签名三者一致 | 200 + 数字 |
| 错位包 | 表单 page 与载荷里的 page 差 1 | 200 + nums:[] |
| 废签包 | sign 是固定摆设串 | 200 + nums:[] |
| 噪声包 | enc 全零 | 200 + nums:[] |
| 近亲假钥包 | 用 Fatdog_lovely 完整构造 | **点名 403** |

**静态路线**

1. jadx：根包全部可读，找到 `Zr.bindKeyClass(com.fatdog.reverse.q.Ke.class)`——顺着进 q 包（已被改名的类里找带 int[] 码点表的），还原前半 `Fatdog_`。
2. IDA 打开 libquill.so：导出表有 `Zr_bindKeyClass / nativeEnc / nativeSign / JNI_OnLoad`；`.data` 里 `KEY31_B`（UTF-16LE）读出后半 `lonely`；拼合即 `Fatdog_lonely`。
3. Python 复刻（先 `python server.py`，只发真包）：

```python
import time, hmac, hashlib, requests

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray(); a = b = 0
    for ch in data:
        a = (a + 1) % 256; b = (b + S[a]) % 256
        S[a], S[b] = S[b], S[a]
        out.append(ch ^ S[(S[a] + S[b]) % 256])
    return bytes(out)

KEY  = b"Fatdog_lonely"
BASE = "https://127.0.0.1:8443"

total = 0
for page in range(1, 101):
    ts   = int(time.time())
    enc  = rc4(KEY, f"page={page}&ts={ts}".encode()).hex()
    sign = hmac.new(KEY, enc.encode(), hashlib.sha256).hexdigest()
    r = requests.post(f"{BASE}/api/l31",
                      data={"page": page, "ts": ts, "enc": enc, "sign": sign},
                      verify="certs/ca.crt", timeout=10)
    total += sum(r.json()["nums"])          # 假包返回空列表，sum 自然为 0
print("总和:", total)                        # 50768
```

**Frida 动态路线**：hook `Zr.nativeEnc`/`nativeSign` 直接拿现成 enc/sign（连算法都不用懂）；想看跨层取件瞬间就 hook libart 的 `CallStaticObjectMethod`。陷阱：`Pw.FAKE_KEY = Fatdog_lovely` 与真钥一字之差，用它构造的包会被服务器点名 403。


---


### 关卡 32：心魔哨兵（native 反检测 + 静默投毒）

**考点**：libraven.so 的 JNI_OnLoad 会启动四路反检测哨兵并每 2 秒轮询——① `/proc/self/maps` 搜 frida/gadget；② 试连本机 27042/27043；③ 枚举 `/proc/self/task/*/comm` 找 gum-js-loop/gmain/gdbus；④ TracerPid 非 0 报警（另加 ptrace 占坑，只挡 gdb）。**任何一路命中都不闪退**：全局 g_poison 置位后，每次签名把密钥第 5 字节异或 0x01（Fatdog_anxious → 一字之差），签出来的名全部无效；App 仅在首次确认污染时弹一次"环境异常警告"。

**症状识别**：挂着 Frida 时所有页请求 403、App 有"环境异常警告"弹窗 → 哨兵在投毒，不是网络问题。

**路线 A：静态复刻（全程免疫）**

完全不碰运行时就没有投毒：

```python
import time, hmac, hashlib, requests

KEY  = b"Fatdog_anxious"                # strings -el libraven.so 可见（UTF-16 存放）
BASE = "https://127.0.0.1:8443"

total = 0
for page in range(1, 101):
    ts   = int(time.time())
    sign = hmac.new(KEY, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()
    r = requests.get(f"{BASE}/api/l32", params={"page": page, "ts": ts, "sign": sign},
                     verify="certs/ca.crt", timeout=10)
    total += sum(r.json()["nums"])
print("总和:", total)                    # 51745
```

**路线 B：动态党拆哨兵（三选一）**

1. **洗指纹**：frida-server 改名换监听端口（`./fs -l 0.0.0.0:6666` + `adb forward`），配合 strongR-frida 去掉 LIBFRIDA 魔数与特征线程名——四路哨兵全部失明。
2. **偏移 Hook**：IDA 定位 `k32_scan_once`（引用了 "/proc/self/maps" 与 "TracerPid:" 字符串的函数），`Interceptor.replace(mod.base.add(偏移), new NativeCallback(function(){}, 'void', []))` 让扫描变成空操作。
3. **洗地流**：hook libc 的 `fopen`/`fgets`——读到含 frida 的 maps 行就跳过、读到 TracerPid 行就改写成 0（教程 22 §14 的泛化版）。

**坑位提醒**：`Dn.FAKE_KEY = Fatdog_tense` 是诱饵；别看到"环境异常"就去 hook isPoisoned——那只是关掉弹窗，签名照样是错的，服务器依然 403。

**进阶 Frida 训练——`Interceptor.replace` 完整替换 vs `Interceptor.attach`**：

本关的路线 B 提到了 `Interceptor.replace`，但没有展开。与 `Interceptor.attach`（保留原函数、前后插入逻辑）不同，`Interceptor.replace` 是**整体替换**——原函数完全不执行：

```javascript
// hook_l32_replace.js — Interceptor.replace 训练
Java.perform(function () {
    var mod = Process.findModuleByName('libraven.so');

    // 假设 IDA 里找到 k32_scan_once 的偏移（引用了 "/proc/self/maps" 的函数）
    // 用 Interceptor.attach 先确认偏移正确：
    // Interceptor.attach(mod.base.add(0x1234), {
    //     onEnter: function (a) { console.log('[scan_once] called'); }
    // });

    // 确认后，用 Interceptor.replace 整体替换为空函数：
    var scanAddr = mod.base.add(0x1234);  // k32_scan_once 偏移
    Interceptor.replace(scanAddr, new NativeCallback(function () {
        // 空函数：哨兵扫描什么都不做
        // 注意：返回类型要和原函数匹配（这里假设返回 void）
        console.log('[scan_once] replaced → no-op');
    }, 'void', []));

    // 对比：Interceptor.attach 只是"挂钩"，原函数仍然执行
    // Interceptor.replace 是"换体"，原函数完全不跑
    // 场景选择：
    //   attach = 观察/修改参数或返回值，保留原逻辑
    //   replace = 原逻辑本身就是威胁，需要完全消除
});
```

> **训练点**：`Interceptor.replace(addr, new NativeCallback(fn, returnType, argTypes))` 用一个 NativeCallback 完全替代原函数。原函数的指令不会被执行（但仍在内存中）。选择依据：`attach` 适合"观察+微调"，`replace` 适合"消除威胁"。注意返回类型和参数类型必须与原函数匹配，否则会 crash。

---


### 关卡 33：金刚不坏（CRC 自校验 + 记账守卫）

**考点**：libsable.so 在 `JNI_OnLoad` 里用 dladdr 定位自身基址、解析 ELF 程序头找到可执行段（PT_LOAD/PF_X），对整段算 **CRC32 存入全局基线 g_baseline**；此后每次 `nativeSign` 都重算比对，不一致即静默投毒（密钥第 8 字节异或 0x01）——**连只观察的 inline hook 都会改字节而被抓**。另有 `assertGuard(minTicks)` 记账守卫：ticks 不递增（说明有人整体替换了 nativeSign）同样判负。

**关键线索（IDA 可见）**：导出表里有一对空函数 `K33_ZONE_START / K33_ZONE_END`——CRC 计算把这段区间**挖掉了**（校验器 k33_check 就住在里面）。这个洞既是提示，也是解法②的安全保证。

**三条官方解法（全开，任选其一）**

```javascript
// 解法①（推荐）：spawn 注入，抢在体检之前完成伪装
// frida -U -f com.fatdog.reverse -l hook33.js   （CLI 敲 %resume）
Java.perform(function () {
    var onLoad = Module.findExportByName('libsable.so', 'JNI_OnLoad');
    Interceptor.attach(onLoad, {
        onEnter: function (args) {          // 此刻还没建基线
            var mod = Process.findModuleByName('libsable.so');
            var sign = Module.findExportByName('libsable.so',
                        'Java_com_fatdog_reverse_Fh_nativeSign');
            if (sign) Interceptor.attach(sign, { /* 三联单观察 */ });
            // 这里装的所有钩子都会进入随后的基线 → 永远一致
        }
    });
});

// 解法②：偏移 hook 校验器 k33_check（它在挖洞区间内，改它不动 CRC）
// var mod = Process.findModuleByName('libsable.so');
// Interceptor.attach(mod.base.add(k33_check_offset), {
//     onLeave: function (retval) { retval.replace(1); } });

// 解法③：找到 g_baseline 全局变量（IDA 里看谁写了 k33_text_crc 的返回值），
// Memory 写入当前实值：
// Memory.protect(addr, 4, 'rw-'); addr.writeU32(mod.base.add(...).readU32());
```

注意：`Interceptor.replace` 整体替换 nativeSign 会被 `assertGuard` 抓包（ticks 踏步）——要么别替换只观察，要么连记账一起伪造。

**静态路线（全程免疫）**

完全不碰运行时就没有体检压力：

```python
import time, hmac, hashlib, requests

KEY  = b"Fatdog_jealous"                # strings -el libsable.so 可见
BASE = "https://127.0.0.1:8443"

total = 0
for page in range(1, 101):
    ts   = int(time.time())
    sign = hmac.new(KEY, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()
    r = requests.get(f"{BASE}/api/l33", params={"page": page, "ts": ts, "sign": sign},
                     verify="certs/ca.crt", timeout=10)
    total += sum(r.json()["nums"])
print("总和:", total)                    # 49502
```

**坑位提醒**：`Hk.FAKE_KEY = Fatdog_vain` 是诱饵；解法①记得用 spawn 模式（attach 半路上车时基线早已建好，来不及了）。

**进阶 Frida 训练——`Memory.patchCode` 指令级热补丁**：

本关的解法②提到"偏移 hook 校验器 k33_check"，但没有展开具体的 patch 写法。`Memory.patchCode` 可以直接修改 SO 的机器指令，比 `Interceptor.replace` 更精细：

```javascript
// hook_l33_patch.js — Memory.patchCode 训练
Java.perform(function () {
    var mod = Process.findModuleByName('libsable.so');

    // 假设 IDA 里找到 k33_check 函数（CRC 校验器）的偏移
    // 函数原型：int k33_check(void) → 返回 1 通过，0 失败
    // 目标：把函数体替换为 "mov w0, #1; ret"（ARM64 恒返回 1）

    var checkAddr = mod.base.add(0x5678);  // k33_check 偏移

    // ARM64 指令编码：
    // mov w0, #1  → 0x52800020
    // ret         → 0xD65F03C0
    Memory.patchCode(checkAddr, 8, function (code) {
        var writer = new Arm64Writer(code, { pc: checkAddr });
        writer.putInstruction('mov w0, #1');
        writer.putInstruction('ret');
        writer.flush();
    });

    console.log('[k33_check] patched → always return 1');

    // 对比三种替换方式：
    // 1. Interceptor.attach   → 挂钩，原函数仍执行（会被 CRC 抓到）
    // 2. Interceptor.replace  → 整体替换，但原指令仍在（CRC 可能仍能扫到）
    // 3. Memory.patchCode     → 直接改指令字节，CRC 重算时看到的是新指令
    // 本关因为 CRC 校验整个 .text 段，patchCode 改完后 CRC 基线就匹配了
});
```

> **训练点**：`Memory.patchCode(addr, size, callback)` 在 callback 里直接写入新指令。ARM64 用 `Arm64Writer`，ARM 用 `ArmWriter`。与 `Interceptor.replace` 的区别：replace 是 Frida 框架接管调用（原指令仍在但不执行），patchCode 是直接改掉指令字节（CPU 执行的就是新指令）。本关的 CRC 校验会重算整个 .text 段，所以必须用 patchCode 才能让 CRC 匹配。

---


### 关卡 34：万法归墟（综合卷：Feistel + HMAC + 响应 RC4）

**考点**：前期所学一关收束——真身经 JNI_OnLoad 动态注册（导出表只有两个废诱饵）；参数加密用自定义 **Feistel8**（纯猜必死）；签名 HMAC-SHA256；响应体再裹一层 RC4 且密钥靠**派生**得到；外加四路反检测哨兵、CRC 自校验、记账守卫的全家桶（任一失守静默投毒一字节）。

**协议还原（IDA 读 k34_pack/k34_sign/k34_unwrap）**

```text
key     = "Fatdog_grumpy"                        # UTF-16 存放，strings -el 可见
sub_i   = SHA256(key + str(i))[:4]               # i = 0..7
F_i(x)  = SHA256(sub_i || x)[:4]
enc     = hex( Feistel8( payload ) )             # payload 零填充至 8 的倍数
        # 每块 (L,R)：for i in 0..7: (L,R) = (R, L ^ F_i(L))
sign    = hex( HMAC-SHA256(key, enc) )
rsp_key = SHA256(key + "|rsp")[:16]              # 响应密钥靠派生
响应体   d = hex( RC4(rsp_key, "page=N|nums=a,b,…") )
```

**路线一：纯 Frida** —— spawn 下 hook JNI_OnLoad 的 onEnter 抢先装钩子 → hook libart `_ZN3art3JNI15RegisterNatives...` 抓映射 → 按偏移 attach k34_pack/k34_sign/k34_unwrap 观察三联单 → 复刻或直接转发现成值。

**路线二：patch so** —— IDA 定位 k34_scan_once 与 k34_crc_ok，把函数头改成 `mov w0, #1; ret`（或直接 nop 掉调用点），重打包安装——哨兵与体检同时失明。

**路线三：unidbg（离线签名机）** —— 本关 native 不回调 Java（对比 L31），补环境最省：载入 libtalon.so、调 JNI_OnLoad、然后直接 call RegisterNatives 绑定的 k34_pack 地址喂 page/ts 即得 enc/sign，吞吐量拉满且不怕任何设备端检测。

**Python 全复刻（先 python server.py）**

```python
import time, hmac, hashlib, requests

KEY  = b"Fatdog_grumpy"
RSP  = hashlib.sha256(b"Fatdog_grumpy|rsp").digest()[:16]
SUBS = [hashlib.sha256(KEY + str(i).encode()).digest()[:4] for i in range(8)]

def F(i, x): return hashlib.sha256(SUBS[i] + x).digest()[:4]

def feistel_enc(data: bytes) -> bytes:
    out = bytearray()
    for off in range(0, len(data), 8):
        L, R = data[off:off+4], data[off+4:off+8]
        for i in range(8):
            L, R = R, bytes(a ^ b for a, b in zip(L, F(i, L)))
        out += L + R
    return bytes(out)

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray(); a = b = 0
    for ch in data:
        a = (a + 1) % 256; b = (b + S[a]) % 256
        S[a], S[b] = S[b], S[a]
        out.append(ch ^ S[(S[a] + S[b]) % 256])
    return bytes(out)

BASE  = "https://127.0.0.1:8443"
total = 0
for page in range(1, 101):
    ts   = int(time.time())
    pad  = (-len(p := f"page={page}&ts={ts}".encode())) % 8
    enc  = feistel_enc(p + b"\x00" * pad).hex()
    sign = hmac.new(KEY, enc.encode(), hashlib.sha256).hexdigest()
    r = requests.post(f"{BASE}/api/l34", verify="certs/ca.crt", timeout=10,
                      data={"page": page, "ts": ts, "enc": enc, "sign": sign,
                            "dev": "fatdog-sim", "ver": "3.4"})
    body = rc4(RSP, bytes.fromhex(r.json()["d"])).decode()
    total += sum(int(x) for x in body.split("|")[1][5:].split(","))
print("总和:", total)                    # 49932
```

**坑位提醒**：`Ak.FAKE_KEY = Fatdog_sore` 是一字之差陷阱；两个同名/近名导出函数全是废值；别只 hook isPoisoned 关弹窗——投毒不改回来，签名照样全错。

**进阶 Frida 训练——`Thread.backtrace` 调用栈回溯**：

本关是综合卷，调用链最长（`dlopen → JNI_OnLoad → RegisterNatives → k34_pack`）。用 `Thread.backtrace` 可以在任意 hook 点打印完整调用栈，理解代码执行路径：

```javascript
// hook_l34_backtrace.js — Thread.backtrace 训练
Java.perform(function () {
    // 先 hook dlopen 看 SO 加载时机
    ['android_dlopen_ext', 'dlopen'].forEach(function (fn) {
        var p = Module.findExportByName(null, fn);
        if (!p) return;
        Interceptor.attach(p, {
            onEnter: function (a) {
                this.name = a[0].readCString();
            },
            onLeave: function () {
                if (this.name && this.name.indexOf('libtalon.so') >= 0) {
                    // 在 SO 加载时打印调用栈，看谁触发的
                    console.log('[dlopen] ' + this.name);
                    console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join('\n  '));
                }
            }
        });
    });

    // hook JNI_OnLoad，打印从 dlopen 到 JNI_OnLoad 的栈
    function hookOnLoad() {
        var addr = Module.findExportByName('libtalon.so', 'JNI_OnLoad');
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                console.log('[JNI_OnLoad] called');
                console.log('  backtrace:');
                console.log('  ' + Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n  '));
            }
        });
    }

    // 延迟 hook（SO 可能还没加载）
    setTimeout(hookOnLoad, 1000);
});
```

> **训练点**：`Thread.backtrace(context, backtracer)` 返回地址数组，`DebugSymbol.fromAddress(addr)` 把地址转成 `模块名!函数名+偏移` 的可读形式。`Backtracer.ACCURATE` 用帧指针回溯（准确但需要帧指针），`Backtracer.FUZZY` 用扫描回溯（兼容但可能不准）。综合关卡的调用链长，用 backtrace 可以看清 `dlopen → JNI_OnLoad → RegisterNatives → 业务函数` 的完整路径。

---


### 关卡 35：双匣暗渡（手写 3DES + SM4 + 干扰包）

**考点**：libumbra.so 文件前半是一排无用变换函数（fake_b64_fold/dead_xor_mix/junk_pad/fake_round_mix，全部被导出当噪音），真正的 SM4 与 3DES 压在文件底部、经函数指针表派发。认算法不靠名字靠**魔数**：DES 的 S1 盒开头 `14 04 0d 01`、PC1/PC2 表；SM4 的 S 盒开头 `d6 90 e9 fe`、FK `a3b1bac6`。密钥不异或——由 UTF-16 标记 `Fatdog_sneak` 运行时派生：

```text
sm4_key = SHA256("Fatdog_sneak|sm4")[:16]
des_key = SHA256("Fatdog_sneak|3des")[:24]
```

**请求协议**（POST 表单）：`e1 = hex(SM4(sm4_key, "page=N&ts=T" 零填充))`、`e2 = hex(3DES(des_key, 大端 ts 八字节))`、`sign = HMAC-SHA256(Fatdog_sneak, e1+"|"+e2)`——加密参数恰好两个，外加动态 ts 防重放。

**干扰包甄别**（每页三连发，字段同形）：真包 / 错位包（表单页号与载荷差 1）/ 废签包。服务端裁决与 L31 同款：真钥全对返回数字，其余返回 `nums:[]` 形似而空；用近亲假钥 `Fatdog_skulk` 完整构造的请求会被点名 403。

**第一步：拿标记**

```text
strings -el libumbra.so     # UTF-16 扫描：Fatdog_sneak 现形
```

**第二步：Python 全复刻（先 python server.py）**

```python
import time, hmac, hashlib, requests
from Crypto.Cipher import DES as _D

def sm4_encrypt(data: bytes, key: bytes) -> bytes:
    # 纯 Python SM4-ECB：与服务端 server.py 的实现一致，可直接照抄该文件
    ...

def des3_ecb_encrypt(key24: bytes, data8: bytes) -> bytes:
    d1 = _D.new(key24[0:8],  _D.MODE_ECB)
    d2 = _D.new(key24[8:16], _D.MODE_ECB)
    d3 = _D.new(key24[16:24],_D.MODE_ECB)
    return d3.encrypt(d2.decrypt(d1.encrypt(data8)))

MK   = b"Fatdog_sneak"
SM4K = hashlib.sha256(MK + b"|sm4").digest()[:16]
DSK  = hashlib.sha256(MK + b"|3des").digest()[:24]

BASE  = "https://127.0.0.1:8443"
total = 0
for page in range(1, 101):
    ts  = int(time.time())
    payload = f"page={page}&ts={ts}".encode()
    payload += b"\x00" * ((-len(payload)) % 16)
    e1  = sm4_encrypt(payload, SM4K).hex()
    e2  = des3_ecb_encrypt(DSK, ts.to_bytes(8, "big")).hex()
    sign = hmac.new(MK, (e1 + "|" + e2).encode(), hashlib.sha256).hexdigest()
    r = requests.post(f"{BASE}/api/l35", verify="certs/ca.crt", timeout=10,
                      data={"page": page, "ts": ts, "e1": e1, "e2": e2,
                            "sign": sign})
    total += sum(r.json()["nums"])       # 只发真包；干扰包留给自己玩甄别
print("总和:", total)                     # 51217
```

（sm4_encrypt 可直接从 server.py 抄纯 Python 实现；3DES 用 pycryptodome 拼 EDE 即可，无需手写轮函数。）

**动态路线**：偏移 Hook `k35_sm4_ecb` / `k35_des3_ecb`（IDA 里顺着函数指针表找），onEnter 直接 hexdump 明文入参——比静态还原省事得多。注意前半文件的 `k35_fake_*` / `k35_junk_pad` 是无人调用的诱饵，Hook 它们永远不触发。


---


### 关卡 36：查表识君（手写 AES-128 + Base64 藏钥）

**考点**：libvigor.so 文件前半是三个无人调用的诱饵变换函数（k36_fake_swap_pairs/fake_acc_mix/fake_rev），真正的 AES-128 压在文件底部经指针表派发。认算法靠魔数：S 盒开头 `63 7c 77 7b f2 6b 6f c5`。密钥藏法不走异或——`.rodata` 里躺着一个 24 字符、以 `==` 结尾的 **Base64 串**，运行时 b64decode 得到 16 字节 AES 钥匙（Base64 不是加密，教程 02 的老朋友换个战场）。

**协议还原**

```text
key     = base64decode("tE5zEyf1b+fe49uJN4cY7w==")     # strings 直接可见的"藏宝图"
enc     = hex( AES-128-ECB(key, "page=N&ts=T" 零填充) )
sign    = hex( HMAC-SHA256(mac, enc) )                  # mac = SHA256("Fatdog_break|mac")
```

**第一步：找钥匙**

```text
strings libvigor.so | findstr "=="
# tE5zEyf1b+fe49uJN4cY7w==   ← 24 字符、等号结尾：教科书式 Base64
```

**第二步：Python 全复刻（先 python server.py）**

```python
import time, hmac, hashlib, requests, base64
from Crypto.Cipher import AES

KEY  = base64.b64decode("tE5zEyf1b+fe49uJN4cY7w==")      # 16 字节 AES-128 钥匙
MAC  = hashlib.sha256(b"Fatdog_break|mac").digest()
BASE = "https://127.0.0.1:8443"

total = 0
for page in range(1, 101):
    ts   = int(time.time())
    payload = f"page={page}&ts={ts}".encode()
    payload += b"\x00" * ((-len(payload)) % 16)
    enc  = AES.new(KEY, AES.MODE_ECB).encrypt(payload).hex()
    sign = hmac.new(MAC, enc.encode(), hashlib.sha256).hexdigest()
    r = requests.get(f"{BASE}/api/l36",
                     params={"page": page, "ts": ts, "enc": enc, "sign": sign},
                     verify="certs/ca.crt", timeout=10)
    total += sum(r.json()["nums"])
print("总和:", total)                     # 49495
```

**动态路线**：IDA 里顺着唯一导出入口看到指针表派发 → 底部 `k36_ecb` 就是 AES 本体（偏移 Hook 后 onEnter hexdump 入参直接看明文）。注意前半文件的 `k36_fake_*` 是无人调用的诱饵，Hook 它们永远不触发。

**坑位提醒**：`Oo.FAKE_KEY = Fatdog_bluff` 是一字之差陷阱（命中即 403）；别把 Base64 当加密去"破解"——解码就够了。


---


### 关卡 37：雪崩之谜（SHA-256 变体 IV + RC4 叠加）

**考点**：libwyvern.so 里是一份**被换过血的 SHA-256**——K 表与压缩轮和教科书完全一致（这是"认骨架"的依据），但初始向量 H0 整组替换为 `SHA256("Fatdog_dodge|iv")`；摘要出来还要再过一层 `RC4(SHA256("Fatdog_dodge|rc4")[:16], dg)` 才是最终 sign。于是 hashlib 怎么算都对不上——先认出骨架，再找到两处改动点（IV 换血 + RC4 叠加），谜底自现。

**协议**

```text
iv      = SHA256("Fatdog_dodge|iv")            # 32 字节，整组替换标准 IV
rc4_key = SHA256("Fatdog_dodge|rc4")[:16]
dg      = SHA256变体( payload )                # payload = "page=N&ts=T"，零填充至 64 倍数
sign    = hex( RC4(rc4_key, dg) )
```

**Python 全复刻（先 python server.py；sha37_iv/rc4_37 可直接参考 server.py 内同名函数）**

```python
import time, requests

# —— 与 server.py 完全一致的变体实现（此处引用，省略重复定义）——
from server_sha37 import sha37_iv, rc4_37, IV37_W, RC4K37

BASE  = "https://127.0.0.1:8443"
total = 0
for page in range(1, 101):
    ts   = int(time.time())
    payload = f"page={page}&ts={ts}".encode()
    padded  = payload + b"\x00" * ((-len(payload)) % 64)
    dg   = sha37_iv(padded, IV37_W)              # 换血 IV 压缩
    sign = rc4_37(RC4K37, dg).hex()              # 再叠 RC4
    r = requests.get(f"{BASE}/api/l37",
                     params={"page": page, "ts": ts, "sign": sign},
                     verify="certs/ca.crt", timeout=10)
    total += sum(r.json()["nums"])
print("总和:", total)                    # 51242
```

对拍样例：`variant_sign("page=1&ts=1787013761") = 902ac65869469750db3d5d70cbc89f1221a3a7ccc173ee85f38ff72a9cc53938`。

**动态路线**：spawn 下按偏移 Hook `k37_sha` 入口，dump 第二参数（h[8]）的初始值——发现不是 `6a09e667 bb67ae85…` 而是 `eb9d6a55 e9fce922…`，IV 换血当场实锤；再看出口处 rc4 调用即知第二层。静态路线则全程无需碰设备。

**坑位提醒**：`Sc.FAKE_KEY = Fatdog_drift` 是动词陷阱；K 表魔数在 so 里以 32 位小端字形态存在（IDA 里按 word 看），别用大端字节序列去搜。


---


## Xposed 实战（L38-42）


### 关卡 38：初探模块（findAndHookMethod + 改返回值）

**考点**：`XpGate.check()` 默认返回 false；用 `afterHookedMethod` 的 `param.setResult(true)` 改返回值。

```java
// 模块主类
public class MainHook implements IXposedHookLoadPackage {
    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpp) {
        if (!lpp.packageName.equals("com.fatdog.reverse")) return;
        XposedHelpers.findAndHookMethod("com.fatdog.reverse.XpGate",
                lpp.classLoader, "check", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                param.setResult(true);
            }
        });
    }
}
```

装好后打开关卡 38 页面，onResume 里 `check()` 返回 true → 自动通关。

**答案**：`FLAG_18_L38{puppet_line_attached}`

---


### 关卡 39：偷梁换柱（beforeHookedMethod 篡改入参）

**考点**：`XpVerifier.verifyDevice(deviceId)` 做 SHA256 比对——直接改返回值当然也能过，但本关练的是**篡改参数**。

1. jadx 搜 `FatdogXP` → `CORRECT_ID = "fatdog_xp_2026"`。
2. 在 `beforeHookedMethod` 里替换 args[0]：

```java
XposedHelpers.findAndHookMethod("com.fatdog.reverse.XpVerifier",
        lpp.classLoader, "verifyDevice", String.class, new XC_MethodHook() {
    @Override
    protected void beforeHookedMethod(MethodHookParam param) {
        param.args[0] = "fatdog_xp_2026";   // 偷梁换柱
    }
});
```

进关卡页时 App 用假 id 调一次 verifyDevice，被换成真值后返回 true → 自动通关。

**答案**：`FLAG_18_L39{swap_the_argument}`

---


### 关卡 40：探囊取物（读私有静态字段 + 回传验证）

**考点**：明文私钥只存在 `SecretVault.s_hiddenKey` 私有字段里，jadx 能看到的只有哈希。用 `XposedHelpers.getStaticObjectField` 取出后调 `reportStolenKey(私钥)` 回传——哈希对上 App 自动判定通关。

```java
Class<?> vault = XposedHelpers.findClass("com.fatdog.reverse.SecretVault", lpp.classLoader);
Object key = XposedHelpers.getStaticObjectField(vault, "s_hiddenKey");
XposedHelpers.callStaticMethod(vault, "reportStolenKey", key);
```

也可以顺手 Toast 出来对照：`Fatdog_xp40_secret`。注意只 Toast 不回传是不会通关的——回传那一步才算"得手"。

**答案**：`FLAG_18_L40{secret_field_exposed}`

---


### 关卡 41：斩关夺隘（XC_MethodReplacement 替换方法体）

**考点**：三重校验链 `TripleGate.checkA/checkB/checkC`，checkB 恒假。前两关的 hook 手法都能用，本关官方姿势是 `XC_MethodReplacement` 整体替换：

```java
XposedHelpers.findAndHookMethod("com.fatdog.reverse.TripleGate",
        lpp.classLoader, "checkB",
        XC_MethodReplacement.returnConstant(true));
```

三个检查全真 → 自动通关。（对比：L38 是 after 改结果、L39 是 before 改入参、这关是 replace 换方法体——三种手法各占一关。）

**答案**：`FLAG_18_L41{triple_gate_broken}`

---


### 关卡 42：万剑归宗·不死之身（持久化验证）

**考点**：自毁进程 → 桌面重开 → Hook 仍在。这是 Xposed 与 Frida 的本质区别：Frida 断线即失效，Xposed 模块随系统加载，冷启动照样生效。

```java
XposedHelpers.findAndHookMethod("com.fatdog.reverse.Kl42Gate",
        lpp.classLoader, "coldStartCheck", XC_MethodReplacement.returnConstant(true));
```

操作步骤：挂上模块重启手机 → 打开关卡 42 → 点「自毁进程」（内部会先 tick 再杀自己，防止跳过测试）→ 从桌面重新打开靶场 → 进关卡 42 → 冷启动检测通过且 ticks>0 → 自动通关。如果只 Hook 不自毁，页面会提示"未经过自毁测试"。

**答案**：`FLAG_18_L42{persistence_is_power}`

---


## 签名校验对抗（L43-47）


### 关卡 43：照妖之镜（签名校验对抗 · 开卷）

**考点**：教程 29 的落地第一关。App 启动时 `Wi.audit()` 经 SigningInfo（API28+）/GET_SIGNATURES（旧 API 分支保留）取自身 APK 的 X.509 证书 DER，SHA-256 后与内置基准比对——**通过才解锁提交框**，失败静默无任何提示。基准与 HMAC 标记各拆两半异或分藏两类：信任基准 = `Wi.PA(^0x3C) + Vk.PB(^0x5A)`，HMAC 标记 = `Wi.KA(^0x3C) + Vk.KB(^0x5A)` = `Fatdog_scan`。

**原理**：重打包必换钥匙 → 证书指纹必然改变（原包 3bb2134c…、重签后 efcaccc9…，教程 29 §3 实测），应用只要记住自己人的指纹即可识破。

**协议**：GET https://…:8443/api/l43?page=N&ts=T&sign=HMAC-SHA256("Fatdog_scan", "page=N&ts=T")。

**静态路线（Python 全复刻，先 python server.py）**

```python
import hashlib, hmac, time, requests

KEY = b"Fatdog_scan"
total = 0
for page in range(1, 101):
    ts   = int(time.time())
    sign = hmac.new(KEY, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()
    r = requests.get("https://127.0.0.1:8443/api/l43",
                     params={"page": page, "ts": ts, "sign": sign},
                     verify="certs/ca.crt", timeout=5).json()
    assert len(r["nums"]) == 10, r
    total += sum(r["nums"])
print(total)   # 52236
```

签名校验门禁只影响 App 内提交框，静态复刻党直连取数不受影响。

**动态路线**：重打包后进关会发现提交框灰着（镜子照出了新指纹）。三条路：
① jadx 找到 Wi.audit 把 verdict 改恒真（或 patch equals）；
② Frida hook `getPackageInfo` 把 Signature 字节换成原签名字节；
③ MT/NP 管理器『去签名校验』一键杀。
注意直接 hook MessageDigest 出口返回基准哈希在本关也有效——这是 L49 记账守卫要堵的洞。

**坑位提醒**：`Tg.FAKE_KEY = Fatdog_span` 与真标记一字之差（命中即 403）；基准是 hex 字符串不是原始字节，别拿 DER 摘要的 raw bytes 去比字符串。答案：加和 `52236`；flag `FLAG_18_L43{mirror_tells_true}`


---


### 关卡 44：偷天换日（签名校验对抗 · 摘要下沉 native + 记账守卫）

**考点**：把 L43 的校验链整体搬进 libpearl.so——Java 只负责 `Wk.passCert(certDer)`；so 内完成 SHA-256、与基准（^0x66 数组首次使用时还原）比对、verdict/ticks 记账。发包前 `Wk.guard(1)` 核账，任一异常拦截请求并提示 `完整性校验失败`。

**为什么 L43 的绕法大面积失效**：
① hook Java 摘要出口无效——计算根本不走 `MessageDigest`；
② 整体替换 passCert/assertGuard → g_ticks 不再增长 → assertGuard 返回 -2（踏步现形）；
③ 重打包 verdict 天然为假 → -3。
HMAC 取数本身仍是标准姿势：sign = HMAC-SHA256("Fatdog_forge", "page=N&ts=T")，密钥两半异或分藏 Wk.KA(^0x3C)/Xh.KB(^0x5A)。

**协议**：GET https://…:8443/api/l44?page=N&ts=T&sign=HMAC-SHA256("Fatdog_forge", "page=N&ts=T")。

**静态路线（Python 全复刻，先 python server.py）**

```python
import hashlib, hmac, time, requests

KEY = b"Fatdog_forge"
total = 0
for page in range(1, 101):
    ts   = int(time.time())
    sign = hmac.new(KEY, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()
    r = requests.get("https://127.0.0.1:8443/api/l44",
                     params={"page": page, "ts": ts, "sign": sign},
                     verify="certs/ca.crt", timeout=5).json()
    assert len(r["nums"]) == 10, r
    total += sum(r["nums"])
print(total)   # 49328
```

静态复刻党对 native 守卫天然免疫——守卫只拦 App 内的动态玩家。

**动态路线（三选一）**
① **内存换票**（推荐）：spawn 后 hook t44Activity.getCertDer 的返回（或 SigningInfo 出口），把 DER 字节替换成原包证书的字节——passCert 吃到真证书，verdict=1、ticks 正常，全链无痕；
② IDA 在 .data 找 ^0x66 解密循环 → 定位 nativеVerify 的 memcmp 比较点 → 偏移 Hook 恒等；
③ 运行时 Memory.scanSync 找解出的基准 32 字节（特征：3b ba 13 …），改成当前重签包的指纹——比较自然成立。

**坑位提醒**：整体替换 passCert 是新手必踩的坑（-2 踏步）；`Yk.FAKE_KEY = Fatdog_forgo` 一字之差陷阱（命中即 403）。答案：加和 `49328`；flag `FLAG_18_L44{forged_no_more}`


---


### 关卡 45：移形换影（签名校验对抗 · native 自读 APK 剥 PKCS#7）

**考点**：与 L44 的本质分野——不再向系统要答案。libcoral.so 拿到 `sourceDir` 后全程自己动手：

```text
open(base.apk) -> 整文件读入
-> 从尾部扫 EOCD（PK\x05\x06）
-> 遍历中央目录条目（PK\x01\x02），按名字命中 META-INF/*.RSA|.DSA
-> 回跳 Local File Header 取数据起点（PK\x03\x04 + 名长/附加长）
-> STORED 直拷 / DEFLATED 走 zlib uncompress
-> PKCS#7 DER 里扫描 A0 82 LL LL 容器，其内容第一个 30 82 CC CC 即 X.509 证书
-> SHA-256(certDER) 与 ^0x66 基准比对（记账语义同 L44）
```

因此对 `getPackageInfo / SigningInfo / Signature` 的**任何 Hook 全部失明**——应用根本不问系统。

HMAC 取数不变：sign = HMAC-SHA256("Fatdog_lurk", "page=N&ts=T")，密钥两半异或分藏 Wn.KA(^0x3C)/Yb.KB(^0x5A)。

**协议**：GET https://…:8443/api/l45?page=N&ts=T&sign=HMAC-SHA256("Fatdog_lurk", "page=N&ts=T")。

**静态路线（Python 全复刻，先 python server.py）**

```python
import hashlib, hmac, time, requests

KEY = b"Fatdog_lurk"
total = 0
for page in range(1, 101):
    ts   = int(time.time())
    sign = hmac.new(KEY, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()
    r = requests.get("https://127.0.0.1:8443/api/l45",
                     params={"page": page, "ts": ts, "sign": sign},
                     verify="certs/ca.crt", timeout=5).json()
    assert len(r["nums"]) == 10, r
    total += sum(r["nums"])
print(total)   # 49906
```

守卫只拦 App 内动态玩家，静态复刻直连免疫。

**动态路线（三选一）**
① **IO 重定向**（本关官方主解）：Frida hook libc `open`/`fopen`，当路径含 base.apk 时改指向攻击者预先留存的原始未改包副本——so 读到的仍是原证书，verdict=1 全链无痕；
② IDA 定位 m7 流程中 memcmp 比较点 → 偏移 Hook 恒等；
③ Memory 找解出的基准 32 字节改成当前指纹。
注意整体替换 passApkPath 会 ticks 踏步返回 -2（同 L44）。

**坑位提醒**：`Xv.FAKE_KEY = Fatdog_lark` 与 lurk 一字之差（命中即 403）；so 里找不到明文指纹——基准是 ^0x66 异或存放的非 static 数组。答案：加和 `49906`；flag `FLAG_18_L45{self_read_beats_pm}`

---


### 关卡 46：以签为钥（签名校验对抗 · L4 派生型主打）

**考点**：签名校验对抗的终极大招——没有 if 判断。密钥由证书 DER 派生：

```text
certHash = SHA-256(从 APK 签名中提取的 X.509 证书 DER)
derivedKey = SHA-256(certHash ‖ b"Fatdog_bind")
sign = HMAC-SHA256(derivedKey, "page=N&ts=T")
```

重打包者的证书不同→certHash 不同→derivedKey 不同→HMAC 全部 403——零提示，零 if 判断。服务端用同样的逻辑独立派生相同 key 验签。

**协议**：POST `https://…:8443/api/l46`，表单字段 page、ts、sign。

**静态路线（Python 全复刻，先 python server.py）**

```python
import hashlib, hmac, time, requests

cert_hash = bytes.fromhex("3bb2134ca3b10bacd43965d0838efa90eef3765eed8832929168ca0e221237fe")
derived_key = hashlib.sha256(cert_hash + b"Fatdog_bind").digest()
total = 0
for page in range(1, 101):
    ts   = int(time.time())
    sign = hmac.new(derived_key, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()
    r = requests.post("https://127.0.0.1:8443/api/l46",
                      data={"page": page, "ts": ts, "sign": sign},
                      verify="certs/ca.crt", timeout=5).json()
    assert len(r["nums"]) == 10, r
    total += sum(r["nums"])
print(total)   # 51008
```

**动态路线（三选一）**

1. **Frida hook Wg.nativeSign()**：拦截 JNI 派生函数的返回值，拿到 32 字节 derivedKey 后 Python 复刻——这是官方主解。
2. **unidbg 调 JNI**：直接调 Wg.nativeKeySeed()/nativeSign() 拿派生密钥。
3. **IDA 静态还原**：读 m8.c 里 `BENCH_X[32]` 数组（证书 SHA-256 的 ^0x66 异或存放），XOR 0x66 还原原始 certHash → SHA-256(certHash + "Fatdog_bind") → derivedKey → HMAC 取数。

**坑位提醒**：m8.c 里 `DECOY_KEY = "Fatdog_band"`（bind→band 一字之差）是陷阱；服务端用同样的 certHash 派生验签，但用假 key 派生的请求会被静默拒绝（返回空 nums）。

答案：加和 `51008`；flag `FLAG_18_L46{key_derived_from_cert}`

---


### 关卡 47：幽冥合卷（签名校验对抗收官 · 四重防线）

**考点**：签名校验对抗的终极大考——四重防线同时叠加，任何单一手段都不够：

1. **三点互验记账**（ticks 三路交叉核账）：三个独立计数器互相同步检查，篡改任一计数器会导致三路不一致→拒绝服务
2. **CRC 自校验**（可执行段完整性）：libfelix.so 对自身可执行段做 CRC32 校验，基线在 JNI_OnLoad 建立；任何 inline hook 都会改变 CRC→被检测
3. **certHash 密钥派生**：密钥由证书 DER 派生，重打包者证书不同→派生 key 不同→全部 403
4. **AES 加密响应**：响应不再是明文 nums，而是 AES 加密的密文，需要额外解密步骤

```text
密钥派生：
  certDER   = 从 APK 签名中提取的 X.509 证书 DER
  certHash  = SHA-256(certDER)
  hmac_key  = SHA-256(certHash ‖ b"Fatdog_seal")       # 完整 32 字节
  aes_key   = hmac_key[:16]                              # 前 16 字节

请求签名：
  enc  = hex(AES-ECB(aes_key, "page=N&ts=T" 零填充))
  sign = HMAC-SHA256(hmac_key, enc)

响应解密：
  response = AES-ECB-Decrypt(aes_key, bytes.fromhex(d))
  # 解密后格式: "page=N|nums=1,2,3,..."
```

**协议**：POST `https://…:8443/api/l47`，表单字段 page、ts、sign、enc。响应 `{"d": hex(AES(nums))}`。

**静态路线（Python 全复刻，先 python server.py）**

```python
import hashlib, hmac, time, requests
from Crypto.Cipher import AES

cert_hash = bytes.fromhex("3bb2134ca3b10bacd43965d0838efa90eef3765eed8832929168ca0e221237fe")
hmac_key  = hashlib.sha256(cert_hash + b"Fatdog_seal").digest()
aes_key   = hmac_key[:16]

def pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def aes_ecb_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(plaintext))

def aes_ecb_decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    pad_len = plaintext[-1]
    return plaintext[:-pad_len]

total = 0
for page in range(1, 101):
    ts   = int(time.time())
    enc  = aes_ecb_encrypt(aes_key, f"page={page}&ts={ts}".encode()).hex()
    sign = hmac.new(hmac_key, enc.encode(), hashlib.sha256).hexdigest()
    r = requests.post("https://127.0.0.1:8443/api/l47",
                      data={"page": page, "ts": ts, "sign": sign, "enc": enc},
                      verify="certs/ca.crt", timeout=5).json()
    nums_hex = r["d"]
    plaintext = aes_ecb_decrypt(aes_key, bytes.fromhex(nums_hex))
    nums = list(map(int, plaintext.decode().split("nums=")[1].split(",")))
    assert len(nums) == 10, r
    total += sum(nums)
print(total)   # 52437
```

**动态路线（三选一）**

1. **Frida（官方主解）**：spawn 抢跑——在 JNI_OnLoad 之前注入钩子，拦截三点互验记账 + 摘要出口，伪造三路 ticks 一致；Hook CRC 校验器恒返回基线值；拦截 AES 加密出口拿明文 nums。这是本关的标准 Frida 路线。
2. **patch so**：定位 CRC 校验器（k47_crc_check）改字节废掉；定位比较点（memcmp）偏移 Hook 恒等；但注意三点互验需要同时处理三个计数器，否则仍会被检测。
3. **重打包完整复刻**：还原四重防线的所有参数后，用 Python 完整复刻请求+响应解密，完全绕过 App——静态路线免疫所有运行时防线。

**坑位提醒**：
- `Fatdog_steal`（steal）与真标记 `Fatdog_seal`（seal）一字之差，命中即 403 静默拒绝
- CRC 校验器里的假基线值是诱饵——用它建立的基线永远不匹配运行时 CRC
- 记账 ticks 的虚假计数值：三个计数器中有一个会被故意设成错误值，篡改它会导致三路不一致
- AES 加密响应的解密是必须步骤——拿到 `{"d": hex}` 后不解密直接解析会得到乱码
- SEED52=20280426（用于服务端种子验证）

答案：加和 `52437`；flag `FLAG_18_L47{guard_matrix_crc_aes}`


---

## Native大陆（L48-L53）


### 关卡 48：落日平原（手写 TEA · std::map 分发 · JNI 回调 Java 取时间戳）

**考点**：Native大陆首关——全程在 C++ native 层完成加密+签名，JNI 只负责传入 page 和时间戳。手写 TEA（Tiny Encryption Algorithm）对 payload 加密，HMAC-SHA256 签名，POST 协议传输。

```text
协议：POST /api/l48
  表单字段：enc, sign, algo=0
  enc  = hex(TEA-ECB(tea_key, "page=N&ts=T"))
  sign = HMAC-SHA256(hmac_key, enc)
  algo = 0

密钥（XOR 数组解码）：
  tea_key  = Fatdog_sunset_2026（XOR ^0x29）
  hmac_key = Fatdog_plains_2026（XOR ^0x41）
```

**静态路线（Python 全复刻，先 python server.py）**

```python
import hashlib, hmac, time, requests, struct

TEA_KEY = b"Fatdog_sunset_2026"
HMAC_KEY = b"Fatdog_plains_2026"

def tea_encrypt(key, v0, v1):
    mask = 0xFFFFFFFF
    k = struct.unpack('<4I', key.ljust(16, b'\0'))
    delta = 0x9E3779B9
    s = 0
    for _ in range(32):
        s = (s + delta) & mask
        v0 = (v0 + (((v1 << 4) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1]))) & mask
        v1 = (v1 + (((v0 << 4) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3]))) & mask
    return v0, v1

def pkcs7_pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

total = 0
for page in range(1, 101):
    ts = int(time.time())
    payload = f"page={page}&ts={ts}".encode()
    padded = pkcs7_pad(payload)
    # TEA-ECB: 加密每 8 字节块
    enc_bytes = b''
    for i in range(0, len(padded), 8):
        v0, v1 = struct.unpack('<2Q', padded[i:i+8])
        v0, v1 = tea_encrypt(TEA_KEY, v0, v1)
        enc_bytes += struct.pack('<2Q', v0, v1)
    enc = enc_bytes.hex()
    sign = hmac.new(HMAC_KEY, enc.encode(), hashlib.sha256).hexdigest()
    r = requests.post("https://127.0.0.1:8443/api/l48",
                      data={"enc": enc, "sign": sign, "algo": 0},
                      verify="certs/ca.crt", timeout=5).json()
    assert len(r["nums"]) == 10, r
    total += sum(r["nums"])
print(total)
```

**动态路线**：IDA 定位 `nativeEnc` → 追踪 TEA 密钥调度（delta 异或展开 32 轮）→ 还原 XOR 数组 → 静态复刻。本关无反调试、无记账守卫，纯算法识别。

**坑位提醒**：TEA 的 delta `0x9E3779B9` 是黄金比例常量，IDA 里搜这个魔数可以直接定位加密函数。别和 XTEA（delta `0x61C88647`）搞混。

答案：加和 `51680`；flag `FLAG_18_L48{sunset_plains}`


### 关卡 49：迷雾森林（std::map 分发 · SM4-ECB + HMAC-SHA256 · RAII）

**考点**：L48 的升级版——用 std::map 做算法分发（CryptoBox 类），RAII 管理内存（ManagedBuffer），密钥通过 C++ 静态对象延迟初始化。加密换成国密 SM4-ECB，签名仍是 HMAC-SHA256，协议改为 POST。

```text
协议：POST /api/l49
  表单字段：enc, sign, algo=0
  enc  = hex(SM4-ECB(sm4_key, "page=N&ts=T"))
  sign = HMAC-SHA256(hmac_key, enc)
  algo = 0

密钥（XOR 数组解码，分散在 KeyProvider 类中）：
  sm4_key  = Fatdog_mist_2026（XOR ^0x3C）
  hmac_key = Fatdog_forest_2026（XOR ^0x5A）
```

**静态路线（Python 全复刻，先 python server.py）**

```python
import hashlib, hmac, time, requests

SM4_KEY  = b"Fatdog_mist_2026"
HMAC_KEY = b"Fatdog_forest_2026"

# 需要 pycryptodome 的 SM4 或自己实现 SM4-ECB
from Crypto.Cipher import SM4

def sm4_ecb_encrypt(key, data):
    cipher = SM4.new(key, SM4.MODE_ECB)
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len] * pad_len)
    return cipher.encrypt(padded)

total = 0
for page in range(1, 101):
    ts = int(time.time())
    payload = f"page={page}&ts={ts}".encode()
    enc = sm4_ecb_encrypt(SM4_KEY, payload).hex()
    sign = hmac.new(HMAC_KEY, enc.encode(), hashlib.sha256).hexdigest()
    r = requests.post("https://127.0.0.1:8443/api/l49",
                      data={"enc": enc, "sign": sign, "algo": 0},
                      verify="certs/ca.crt", timeout=5).json()
    assert len(r["nums"]) == 10, r
    total += sum(r["nums"])
print(total)
```

**动态路线**：
1. IDA 定位 `CryptoBox::process` → 理解 `std::map<int, function>` 分发逻辑
2. Frida hook `nativeEnc`/`nativeSign` 观察返回值
3. `Memory.scanSync` 搜索 std::map 内部红黑树节点（SGI STL 红黑树头节点特征：`__rb_tree_node_base` 布局）
4. 静态复刻：还原 SM4 密钥 + HMAC 密钥

**坑位提醒**：
- 标记 `Fatdog_mist`（真）与 `Fatdog_misty`（诱饵 UTF-16）只差一个 `y`——strings 默认搜不到 UTF-16，用 `strings -el` 可破
- SM4 的 S 盒开头 `d6 90 7c b3` 是国密特征，IDA 里搜这 4 个字节直接定位
- RAII 的 `ManagedBuffer` 析构函数里清零内存——动态分析时及时 dump

答案：加和 `50621`；flag `FLAG_18_L49{misty_forest}`


### 关卡 50：幽暗深渊（vtable 虚函数表分发 · AES-128-ECB + SHA-256 + 海量业务代码）

**考点**：vtable 虚函数表分发——真正调用的只有 `AesEngine::encrypt` 和 `Sha256Signer::sign`，但 SO 里有 20+ 个业务类（UserSessionManager、OrderService、PaymentProcessor 等 ~750 行干扰代码），需要从 vtable 指针中识别真正被调用的虚函数。

```text
协议：GET /api/l50?enc=...&sign=...&ts=...
  enc  = hex(AES-128-ECB(aes_key, "page=N&ts=T"))
  sign = SHA-256(enc)          ← 注意：不是 HMAC，是裸 SHA-256
  ts   = Unix 时间戳

密钥（XOR 数组解码，分散在 KeyProvider 类中）：
  aes_key  = Fatdog_abys_2026（XOR ^0x2A，16 字节适配 AES-128）
  hmac_key = Fatdog_depths_2026（XOR ^0x3D）← 用于服务端签名验证
```

**静态路线（Python 全复刻，先 python server.py）**

```python
import hashlib, time, requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

AES_KEY = b"Fatdog_abys_2026"

total = 0
for page in range(1, 101):
    ts = int(time.time())
    payload = f"page={page}&ts={ts}".encode()
    enc = AES.new(AES_KEY, AES.MODE_ECB).encrypt(pad(payload, 16)).hex()
    sign = hashlib.sha256(enc.encode()).hexdigest()   # 裸 SHA-256，不是 HMAC
    r = requests.get("https://127.0.0.1:8443/api/l50",
                     params={"enc": enc, "sign": sign, "ts": ts},
                     verify="certs/ca.crt", timeout=5).json()
    assert len(r["nums"]) == 10, r
    total += sum(r["nums"])
print(total)
```

**动态路线（Frida vtable 枚举）**：

```javascript
// 枚举 vtable：读取对象头部指针 → 按 sizeof(void*) 步进列出所有虚函数地址
var aesEnginePtr = ptr("0x..."); // 从构造函数或 new 行为定位
var vtablePtr = aesEnginePtr.readPointer();
console.log("vtable @", vtablePtr);
for (var i = 0; i < 10; i++) {
    var fn = vtablePtr.add(i * Process.pointerSize).readPointer();
    console.log("  vtable[" + i + "] =", fn);
}
// 只 hook vtable[0]（encrypt），忽略其他业务类
Interceptor.attach(fn, {
    onEnter: function(args) { this.data = args[1]; },
    onLeave: function(retval) { console.log("enc =", this.data.readUtf8String()); }
});
```

**坑位提醒**：
- 签名是裸 `SHA-256(enc)`，不是 HMAC——这和 L48/L49 不同，别套 HMAC 公式
- 20+ 业务类的虚函数占满 vtable 前面位置，真正的 `encrypt` 可能在 vtable 偏移靠后的位置
- `Fatdog_pearl`（真标记）和 `Fatdog_red`（诱饵 UTF-16）用 `strings -el` 对比
- vtable 指针是内存地址，每次运行都变——Frida hook 不能硬编码偏移

答案：加和 `49873`；flag `FLAG_18_L50{abyssal_depths}`


### 关卡 51：雷霆山巅（3DES-EDE-ECB + SM3 + HMAC-SHA256 · 3 SO 分离）

**考点**：L50 的升级版——三重签名算法（3DES 对称加密 + SM3 哈希 + HMAC-SHA256 签名）分布在三个独立 SO 中，通过 dlopen 依赖链加载。

**静态解法**：
1. 解包 APK 取 `libnative51.so`、`libnative51h.so`、`libnative51b.so`
2. IDA 分析 `libnative51.so`：`nativeSign` 调用 `dlopen("libnative51h.so")` 获取 SM3 和 HMAC 函数指针
3. 密钥派生：`key_3des = SHA256("Fatdog_peak|3des")[:24]`、`key_sm3 = SHA256("Fatdog_peak|sm3")`、`key_mac = SHA256("Fatdog_peak|mac")`
4. `enc = hex(3DES_ECB(key_3des, "page=N&ts=T" 零填充))`、`hash = SM3(enc)`、`sign = HMAC-SHA256(key_mac, hash)`
5. `GET /api/l51?page=N&ts=T&enc=…&hash=…&sign=…`

**动态解法**：
```javascript
// hook_l51.js — 3 SO 分离 + dlopen 依赖链
Java.perform(function () {
    var Bk51 = Java.use('com.fatdog.reverse.Bk51');
    Bk51.nativeSign.implementation = function (page, ts) {
        var result = this.nativeSign(page, ts);
        console.log('[Bk51.nativeSign] page=' + page + ' ts=' + ts + ' sign=' + result);
        return result;
    };
});
// 也可以 hook dlopen 观察 SO 加载顺序
Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
    onEnter: function (args) {
        console.log('[dlopen] ' + args[0].readCString());
    }
});
```

**坑位提醒**：
- 三个 SO 必须同时存在，缺任何一个 `dlopen` 失败导致崩溃
- SM3 是国密哈希算法，标准库没有——必须从 `libnative51h.so` 的导出函数还原
- `libnative51b.so` 是纯业务代码干扰（ThreadPool/EventBus/MetricsCollector/CircuitBreaker/RateLimiter），与加密无关
- `Fatdog_peak`（真标记）和 `Fatdog_pick`（诱饵 UTF-16）用 `strings -el` 对比

答案：加和 `50247`；flag `FLAG_18_L51{thunder_peak}`


### 关卡 52：冰封雪域（魔改 SM4 + 深层调用栈 + HMAC-SHA256 · 3 SO 分离）

**考点**：L51 的升级版——魔改 SM4（S 盒 4 处换值 + FK 异或 + CK 循环左移）+ 深层调用栈（5+ 层）+ 海量业务代码干扰（8 个类 ~1500 行）。

**静态解法**：
1. 解包 APK 取 `libnative52.so`、`libnative52k.so`、`libnative52b.so`
2. IDA 分析 `libnative52.so`：识别魔改 SM4（S 盒魔数 0xd6,0x90,0xe9…可认出骨架），找到 4 处换值（0x3A/0x7F/0xB2/0xE8）
3. 密钥：`libnative52k.so` 导出 `getSm4Key()`/`getHmacKey()`，XOR 数组 ^0x3C 还原
4. `enc = hex(SM52_ECB(sm4_key, "page=N&ts=T"))`、`sign = HMAC-SHA256(hmac_key, "page=N&ts=T")`
5. `GET /api/l52?page=N&ts=T&enc=…&sign=…`

**动态解法**：
```javascript
// hook_l52.js — 深层栈回溯 + dlopen 依赖链
Java.perform(function () {
    var Bk52 = Java.use('com.fatdog.reverse.Bk52');
    Bk52.nativeSign.implementation = function (page, ts) {
        var result = this.nativeSign(page, ts);
        console.log('[Bk52.nativeSign] page=' + page + ' ts=' + ts + ' sign=' + result);
        // 深层栈回溯
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n'));
        return result;
    };
    Bk52.nativeEnc.implementation = function (data) {
        var result = this.nativeEnc(data);
        console.log('[Bk52.nativeEnc] data=' + data + ' enc=' + result);
        return result;
    };
});
```

**坑位提醒**：
- 魔改 SM4 的 S 盒与标准只差 4 个字节——肉眼几乎看不出差异，需逐字节比对
- `libnative52b.so` 有 8 个业务类（InventoryService/ShippingCalculator/UserPreferenceStore/DataSyncer/ReportGenerator/BackupManager/NotificationService/RateLimiter），每个类 5-8 个方法，纯干扰
- 深层调用栈：JNI → k52_dispatch → k52_process → Sm52Cipher::encryptBlock → k52_sm4_round × 32 → k52_sub_bytes
- `Fatdog_snow`（真标记）和 `Fatdog_snowflake`（诱饵 UTF-16）用 `strings -el` 对比

答案：加和 `50247`；flag `FLAG_18_L52{frozen_snowfield}`

### L53：焚天火域（★★★★★ 魔改 AES + Feistel 轮函数 + 异常控制流 · 3 SO 分离 · 最终关）

**加密**：Feistel（32 字节分组，8轮×3子密钥）+ 独立魔改 AES（16 字节分组，S盒4处替换 0x3A/0x7F/0xB2/0xE8 + FK异或 + 密钥扩展3变体 + 变体列混合）+ HMAC-SHA256 签名 + RC4 响应加密

**协议**：`POST /api/l53` 表单 `page=1&ts=T&enc=hex(Feistel)&aes=hex(AES变体)&sign=HMAC`
响应：`{"d": hex(RC4_enc(json))}`

**SO 架构**：native53（调度+异常控制流）+ native53c（加密核心+密钥）+ native53b（22类业务干扰 ~1500+ 行）

**静态解法**：IDA 分析 3 个 SO：
1. native53：`k53_dispatch` → `ErrorHandler::process`（try/catch 藏真逻辑，先对输入 XOR 0x5A）→ `CipherFactory::create`（vtable 分发：algo=1 Feistel，algo=2 独立魔改 AES）
2. native53c：魔改 S 盒 + FK 异或（`0x5254465F, 0x4C33335F, 0x46495245, 0x5F4D4B35`）+ 共用密钥扩展；`k53FeistelEncrypt` 和 `k53AesVariantEncrypt` 分别实现两条轮结构
3. 密钥：混淆数组 A/B/C 各 XOR 0x3C → AES key / HMAC key / RC4 key
4. native53b：22 个业务类（ScoringService, LeaderboardService, TournamentService, CacheManager, RateLimiter, CircuitBreaker, HealthMonitor, MetricsCollector, TelemetryEngine, AnalyticsPipeline, ResourceManager, QueueProcessor, JobScheduler, RetryPolicy, FallbackHandler, LoadBalancer, ServiceRegistry, ConfigManager, SecretRotator, AuditLogger, AlertManager, IncidentTracker），纯干扰

**动态解法**：Frida hook Bk53.nativeSign/nativeEnc 拿明文 payload → Python 复刻

```javascript
// hook_l53.js — 异常控制流追踪 + 密钥提取
Java.perform(function () {
    var Bk53 = Java.use('com.fatdog.reverse.Bk53');
    Bk53.nativeSign.implementation = function (data) {
        var result = this.nativeSign(data);
        console.log('[Bk53.nativeSign] data=' + data + ' sign=' + result);
        return result;
    };
    Bk53.nativeEnc.implementation = function (data, algo) {
        var result = this.nativeEnc(data, algo);
        console.log('[Bk53.nativeEnc] data=' + data + ' algo=' + algo + ' enc=' + result);
        return result;
    };
});
```

**Python 复刻**：
```python
import hashlib, hmac, struct

# 魔改 S 盒（4 处替换）
SBOX = [ ... ]  # 标准 AES S 盒
SBOX[0x63] = 0x3A; SBOX[0x7C] = 0x7F; SBOX[0x77] = 0xB2; SBOX[0x7B] = 0xE8

# FK 异或
FK_XOR = [0x5254465F, 0x4C33335F, 0x46495245, 0x5F4D4B35]

# 密钥（XOR 0x3C 还原）
AES_KEY  = b"Fatdog_aes_key_\x00"
HMAC_KEY = b"Fatdog_hmac_k53\x00"
RC4_KEY  = b"Fatdog_rc4_k53\x00\x00"

# Feistel + AES 变体 + HMAC-SHA256 + RC4（复刻 native53c 两条加密分支）
# ...

# 批量取数
import requests
total = 0
for page in range(1, 101):
    payload = f"page={page}&ts={ts}"
    masked = bytes(b ^ 0x5A for b in payload.encode())
    enc = feistel_encrypt(masked, AES_KEY).hex()
    aes = aes_variant_encrypt(masked, AES_KEY).hex()  # 独立 16 字节分组路径
    sign = hmac.new(HMAC_KEY, payload.encode(), hashlib.sha256).hexdigest()
    resp = requests.post("http://host:5000/api/l53",
                         data={"page": page, "ts": ts, "enc": enc, "aes": aes, "sign": sign})
    d = resp.json()["d"]
    nums = json.loads(rc4_decrypt(RC4_KEY, bytes.fromhex(d)))["nums"]
    total += sum(nums)
print(total)  # 50446
```

**坑位提醒**：
- 异常控制流：`ErrorHandler::process` 的 try 块是空的，真逻辑藏在 catch 块里——IDA 跟 catch 分支
- Feistel 轮函数每 3 轮用不同子密钥（variant 0/1/2），密钥扩展也有 3 个变体
- native53c 对外用 `k53FeistelEncrypt` / `k53AesVariantEncrypt` / `k53Rc4Crypt` 三个 C 导出；内部 `aesEncrypt`、`rc4Encrypt` 仍是 C++ mangled 名
- 22 个业务类（ScoringService 到 IncidentTracker）约 1500+ 行纯干扰代码

答案：加和 `50446`；flag `FLAG_18_L53{scorched_fireland}`


## 天地秘境 · 昆仑山（KL1-5）


### KL1：山门（xorshift32）

**解法**：解包 APK 取 libcedar.so → IDA 看 kl_gate = xorshift32 七轮（`x^=x<<13; x^=x>>17; x^=x<<5;`）→ 种子 `0x20260101 ^ 0x4B554E4C("KUNL")`。

```python
x=0x20260101^0x4B554E4C; M=0xFFFFFFFF
for _ in range(7):
    x^=(x<<13)&M; x&=M
    x^=x>>17
    x^=(x<<5)&M; x&=M
print(x-(1<<32) if x>=(1<<31) else x)   # -303563272
```


### KL2：引雷桩（动态注册 + 诱饵）

**关键**：必须先调 JNI_OnLoad 触发 RegisterNatives。跳过这步会命中同名诱饵导出（返回 `seed ^ 0xDEAD` = 539417775，错误答案）。

真身算法：LCG 步进+折半异或+混合。

```python
x=(0x20260202*0x41C64E6D+0x3039)&0xFFFFFFFF
x=((x>>16)^x)&0xFFFFFFFF
x=(x*0x45D9F3B)&0xFFFFFFFF
print(x-(1<<32) if x>=(1<<31) else x)   # -2146415444
```


### KL3：渡鸦桥（跨层回调）

**原理**：nativeKey() 内部经 GetStaticMethodID/CallStaticObjectMethod 回调 Java 层的 Ku3.halfA() 取前半密钥 "Fatdog_"，与 so 内 UTF-16 后半 "raven" 拼成完整密钥。

**unidbg 补桩**：

```java
@Override
public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvc, String sig, VarArg va) {
    if (sig.equals("com/fatdog/reverse/Ku3->halfA()Ljava/lang/String;"))
        return new StringObject(vm, "Fatdog_");
    return super.callStaticObjectMethod(vm, dvc, sig, va);
}
```

提交 **Fatdog_raven** 即通关。


### KL4：冰裂缝（反模拟检测）

**考点**：nativeProbe() 读 `/proc/self/maps` 搜 unidbg/unicorn 特征，读 `/proc/self/status` 查 TracerPid 非 0。任一命中返回 `ERR_EMULATED`；全部干净返回 `Fatdog_glacier_unlocked`。

**真机上天然通过**——因为真机的 maps 和 status 里没有 unidbg 特征且没有调试器附着。

**unidbg 补法（核心教学点）**

```java
// 在创建模拟器之后、加载 so 之前：
emulator.getSyscallHandler().addIOResolver(new IOResolver() {
    @Override
    public FileResult resolve(Emulator emulator, String pathname, int oflags) {
        if (pathname.equals("/proc/self/maps")) {
            // 喂一份干净的 maps——不含任何 unidbg/unicorn 字样
            String cleanMaps = "7f000000-7f001000 r-xp 00000000 00:00 0  /system/lib/libc.so\n"
                             + "7f002000-7f003000 r--p 00001000 00:00 0  /system/lib/libc.so\n";
            return FileResult.success(new ByteArrayFileIO(oflags, pathname,
                    cleanMaps.getBytes()));
        }
        if (pathname.equals("/proc/self/status")) {
            // 喂假的 status——TracerPid 固定 0
            String cleanStatus = "Name:\tcom.fatdog.reverse\n"
                               + "TracerPid:\t0\n"
                               + "Uid:\t10000\t10000\t10000\t10000\n";
            return FileResult.success(new ByteArrayFileIO(oflags, pathname,
                    cleanStatus.getBytes()));
        }
        return null;   // 其他路径走默认
    }
});
```

然后正常调 `nativeProbe()` 即可拿到 `"Fatdog_glacier_unlocked"`。

**坑位提醒**：如果 IOResolver 返回 null（没拦截），so 会尝试读真实文件系统——在 unidbg 模拟器里这些路径不存在或内容不对，就会触发检测。


---


### KL5：登顶（综合卷）

**考点**：动态注册（JNI_OnLoad 无 RegisterNatives 但有回调依赖）+ 跨层回调（summitKey()）+ XOR 解密。

**原理**：nativeClimb 回调 Ku5.summitKey() 取 "Fatdog_"，与 so 内 UTF-16 后半 "summit" 拼成 "Fatdog_summit"，XOR 解密内嵌加密数据得明文 `summit_of_kunlun_2026`。

**unidbg 补桩**：

```java
@Override
public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvc, String sig, VarArg va) {
    if (sig.contains("summitKey"))
        return new StringObject(vm, "Fatdog_");
    return super.callStaticObjectMethod(vm, dvc, sig, va);
}
```

提交 **summit_of_kunlun_2026** 即通关。


---


## 天地秘境 · 流沙河（KL6-10）


### KL6：冰封之钥（流沙河首关 · 魔改 AES-128）

**考点**：libember.so 手写 AES-128——S 盒与压缩结构都是标准的（认骨架够用），但轮常量 Rcon 三处换血（idx3: 08→9e、idx6: 40→77、idx9: 36→d4），标准库永远解不开它自己加密的密文。真标记 `Fatdog_pierce` 以 UTF-16 码元数组藏匿（默认 strings 盲区，`strings -el` 可破）；明文躺着的 `Fatdog_piece` 是一字之差诱饵，用它派生钥匙的请求一律 403；导出函数 `m1_decoy_seal` 返回假密文（用 piece 钥 + 换血 AES 解开是一段像样的假载荷 `page=7&ts=1700000000`）。

**协议**：GET https://…:8443/api/kl6?page=N&ts=T&enc&sign

- enc = hex(魔改AES-128-ECB( sha256("Fatdog_pierce|aes")[:16], "page=N&ts=T" 零填充至 32 字节 ))
- sign = HMAC-SHA256( sha256("Fatdog_pierce|mac"), enc )

对拍样例：page=1&ts=1787013761 →
enc = e30b62fe18082de41cd69fe2a5c1b2142d135b2d50e846caa40bbfb0fa44269c
sign = fdc4ebf471f82276d5811e5f63772fd2a7e32079ec9fbb47b318f9776e34970b

（生成器 gen_kl6.py 内置 FIPS-197 官方向量自测与 pycryptodome 对拍；so 的 C 实现经主机编译与本样例逐字节一致。）

**静态路线（Python 全复刻，先 python server.py）**

```python
import hashlib, hmac, time, requests
from gen_kl6 import ecb_encrypt, pad, RCON_MOD   # 生成器即官方镜像实现

MARKER = b"Fatdog_pierce"
akey = hashlib.sha256(MARKER + b"|aes").digest()[:16]
mack = hashlib.sha256(MARKER + b"|mac").digest()

total = 0
for page in range(1, 101):
    ts   = int(time.time())
    enc  = ecb_encrypt(akey, pad(f"page={page}&ts={ts}".encode()), RCON_MOD).hex()
    sign = hmac.new(mack, enc.encode(), hashlib.sha256).hexdigest()
    r = requests.get("https://127.0.0.1:8443/api/kl6",
                     params={"page": page, "ts": ts, "enc": enc, "sign": sign},
                     verify="certs/ca.crt", timeout=5).json()
    assert len(r["nums"]) == 10, r
    total += sum(r["nums"])
print(total)   # 51561
```

不想依赖生成器也可以手写同款 AES：全套照教科书抄，只把 Rcon 表三处值换成 9e/77/d4——其余一个字节都不要动。

**动态路线**：jadx 从 n43Activity 顺藤摸到 Tj/Vv——Frida `Java.use('com.fatdog.reverse.Tj')` 直接调用 nativeEnc/nativeSign 拿现成参数对拍或转发；IDA 路线则从 S 盒 xref 定位 m1_key_expand，观察轮密钥展开——第 4/7/10 轮起与标准分叉，就是 Rcon 换血的实锤。

**坑位提醒**：`Uu.FAKE_KEY = Fatdog_piece` 与真标记一字之差（命中即 403）；`strings libember.so` 默认看不见真标记，要 `-el`；别把 `m1_decoy_seal` 的密文当宝。答案：加和 `51561`；flag `FLAG_18_KL6{ice_seal_broken}`


---


### KL7：裂魂之匣（流沙河 · 手写魔改 3DES + HMAC）

**考点**：libfrost.so 手写 DES——S 盒骨架可认（S1 开头 `14 04 0d 01`）、E/P/PC1/PC2 全是标准，但三处被动手脚：

1. **IP 排列表首尾互换**：IP[0]=58 ↔ IP[63]=57（IDA 里对表一眼见血——标准 IP 开头是 58,50,42,34）；
2. **FP 同步重算**为魔改 IP 的逆置换（保证它自己加解密回环一致）；
3. **S3 盒第 2 行第 3/4 列两值互换**（扁平下标 18/19：标准值 00,09 被换成 09,00）。

标准 DES 库解不开它加密的密文。真标记 `Fatdog_shatter` 以 UTF-16 码元数组藏匿（默认 strings 盲区）；明文躺着的 `Fatdog_scatter` 是一字之差诱饵，用它派生钥匙的请求一律 403；导出函数 `m2_decoy_seal` 返回假密文。

**协议**：POST https://…:8443/api/kl7（表单 page/ts/enc/sign）

- enc = hex( 魔改 3DES-EDE( sha256("Fatdog_shatter|des")[:24], "page=N&ts=T" 零填充至 8 字节倍数 ) )
- sign = HMAC-SHA256( sha256("Fatdog_shatter|mac"), enc )

对拍样例：page=1&ts=1787013761 →
enc = e85191b8d0428195b7001f1daa537beec638f5261a624b27
sign = e982bc1b3811c23d911588a49df32539c56e43d4c5cc35a78cd1867554a5decf

（生成器 gen_kl7.py 内置教科书向量与 pycryptodome 对拍自测；so 的 C 实现经主机编译与本样例逐字节一致。）

**静态路线（Python 全复刻，先 python server.py）**

```python
import hashlib, hmac, time, requests
from gen_kl7 import ede_encrypt, pad8  # 生成器即官方镜像实现

MARKER = b"Fatdog_shatter"
dk   = hashlib.sha256(MARKER + b"|des").digest()[:24]
mack = hashlib.sha256(MARKER + b"|mac").digest()

total = 0
for page in range(1, 101):
    ts   = int(time.time())
    enc  = ede_encrypt(dk, pad8(f"page={page}&ts={ts}".encode())).hex()
    sign = hmac.new(mack, enc.encode(), hashlib.sha256).hexdigest()
    r = requests.post("https://127.0.0.1:8443/api/kl7",
                      data={"page": page, "ts": ts, "enc": enc, "sign": sign},
                      verify="certs/ca.crt", timeout=5).json()
    assert len(r["nums"]) == 10, r
    total += sum(r["nums"])
print(total)   # 48865
```

不想依赖生成器也可以手写同款 DES：全套照 FIPS 教科书抄，只改三处——IP[0]/IP[63] 互换、FP 按新 IP 重算逆置换、S3[18]/S3[19] 互换——其余一个字节都不要动。（注意 S 盒顺序别背错：`13,2,8,4…` 开头的是 S8 不是 S3，真实 S3 开头 `10,00,09,0e`。）

**动态路线**：jadx 从 o44Activity 顺藤摸到 Tp/Vq——Frida `Java.use('com.fatdog.reverse.Tp')` 直接调用 nativeEncDes/nativeSign 拿现成参数对拍或转发；IDA 路线则从 S1 盒 xref 定位 m2 的 Feistel 函数与子密钥编排，对比 IP 表开头（57,50,42,34 ≠ 标准 58,50,42,34）即实锤第一处魔改。

**坑位提醒**：`Ww.FAKE_KEY = Fatdog_scatter` 与真标记一字之差（命中即 403）；`strings libfrost.so` 默认看不见真标记，要 `-el`；别把 `m2_decoy_seal` 的密文当宝；用标准 pycryptodome 3DES 构造的请求服务端解不开（返回 nums 空数组）——这正是"必须还原魔改点"的反证。答案：加和 `48865`；flag `FLAG_18_KL7{soul_box_shattered}`

---


### KL8：幽泉之眼（流沙河 · 魔改 SM4）

**考点**：libivory.so 手写 SM4——FK 与 S 盒均为标准（认骨架够用），但轮常量 CK 的最后 8 个值（idx24~31）被换血为 sha256("Fatdog_unravel|ck") 派生的 8 个字 → 第 25~32 轮的轮密钥全部跑偏，标准 SM4 解不开本关密文。真标记 `Fatdog_unravel` 以 UTF-16 码元藏匿；明文的 `Fatdog_travel` 是一字之差诱饵（命中即 403）；`m3_decoy_seal` 返回假密文（travel 钥解开是像样的假载荷 page=9&ts=1700000000）。

**协议**：GET https://…:8443/api/kl8?page=N&ts=T&enc&sign

- enc = hex(魔改SM4-ECB( sha256("Fatdog_unravel|sm4")[:16], "page=N&ts=T" 零填充至 32 字节 ))
- sign = HMAC-SHA256( sha256("Fatdog_unravel|mac"), enc )

对拍样例：page=1&ts=1787013761 →
enc = 9afd8e84bb92dded69dc9810a5b3dc8d7b83cfda29a1a0a2e4b79ae02934eeeb
sign = 8decadace63b0ecc2d7f16fcd5e5d347ffec661bbb46650d235bc476dd4aa158

（生成器 gen_kl8.py 内置 GB/T 32907 官方向量自测：key=pt=0123456789abcdeffedcba9876543210 → 681edf34d206965e86b3e94f536e4246，证明除 CK 尾部外全为标准实现。）

**静态路线（Python 全复刻，先 python server.py）**

```python
import hashlib, hmac, time, requests
from gen_kl8 import ecb_crypt, pad, CK_MOD   # 生成器即官方镜像实现

MARKER = b"Fatdog_unravel"
skey = hashlib.sha256(MARKER + b"|sm4").digest()[:16]
mack = hashlib.sha256(MARKER + b"|mac").digest()

total = 0
for page in range(1, 101):
    ts   = int(time.time())
    enc  = ecb_crypt(skey, pad(f"page={page}&ts={ts}".encode()), CK_MOD).hex()
    sign = hmac.new(mack, enc.encode(), hashlib.sha256).hexdigest()
    r = requests.get("https://127.0.0.1:8443/api/kl8",
                     params={"page": page, "ts": ts, "enc": enc, "sign": sign},
                     verify="certs/ca.crt", timeout=5).json()
    assert len(r["nums"]) == 10, r
    total += sum(r["nums"])
print(total)   # 51217
```

手写同款也行：教科书 SM4 一字不改，只把 CK 表最后 8 个值换成派生常量 c464de0e/6dd38813/b920f6b8/489e2834/4569611b/533fa56c/2d881af6/23697441。

**动态路线**：jadx 从 p45Activity 跟到 Uq/Wr——Frida 直接调 `Uq.nativeEnc/nativeSign` 拿现成参数对拍或转发；IDA 从 S 盒/FK 魔数定位 SM4 后观察轮密钥展开——前 24 个 rk 正常、第 25 个起与标准分叉，CK 尾部换血当场实锤。

**坑位提醒**：`Xu.FAKE_KEY = Fatdog_travel` 与 unravel 一字之差（命中即 403）；`strings libivory.so` 默认看不见真标记，要 `-el`；别拿 `m3_decoy_seal` 的密文当宝。答案：加和 `51217`；flag `FLAG_18_KL8{spring_eye_awake}`


---


### KL9：天罡北斗（流沙河 · 魔改 RC4）

**考点**：libjade.so 手写 RC4 双层魔改——① **KSA 的初始 S 盒不是恒等置换** S[i]=i，而是自定义 256 字节置换表（sha256("Fatdog_veil|ksa") 经确定性 Fisher-Yates 派生；IDA 里看 KSA 循环前是查表加载而非递增赋值）；② **PRGA 每字节输出后异或 16 字节循环掩码**（sha256("Fatdog_veil|mask")[:16]）。真标记 `Fatdog_veil` 以 UTF-16 码元藏匿；明文的 `Fatdog_vile` 是一字之差诱饵（命中即 403）；`m4_decoy_seal` 返回假密文（vile 钥解开是像样的假载荷 page=13&ts=1700000000）。

**协议**：GET https://…:8443/api/kl9?page=N&ts=T&enc&sign

- enc = hex(魔改RC4( sha256("Fatdog_veil|rc4")[:16], "page=N&ts=T" 零填充至 32 字节 ))
- sign = HMAC-SHA256( sha256("Fatdog_veil|mac"), enc )

对拍样例：page=1&ts=1787013761 →
enc = 0674e11ca7c9039f0028097740902b1b19589d0505517e4393c15c75cb07780b
sign = a216f6b8a67d9047b746b3ba4c9eea3d6a4311cdf96bcecc12b6d4562b562873

（生成器 gen_kl9.py 内置标准 RC4 公开向量自测：key="Secret"、明文 "Attack at dawn" → 45a01f645fc35b383552544b9bf5，证明除两层魔改外全为标准实现。）

**静态路线（Python 全复刻，先 python server.py）**

```python
import hashlib, hmac, time, requests
from gen_kl9 import rc4_crypt, pad, KSA_INIT, MASK   # 生成器即官方镜像实现

MARKER = b"Fatdog_veil"
rkey = hashlib.sha256(MARKER + b"|rc4").digest()[:16]
mack = hashlib.sha256(MARKER + b"|mac").digest()

total = 0
for page in range(1, 101):
    ts   = int(time.time())
    enc  = rc4_crypt(KSA_INIT, MASK, rkey, pad(f"page={page}&ts={ts}".encode())).hex()
    sign = hmac.new(mack, enc.encode(), hashlib.sha256).hexdigest()
    r = requests.get("https://127.0.0.1:8443/api/kl9",
                     params={"page": page, "ts": ts, "enc": enc, "sign": sign},
                     verify="certs/ca.crt", timeout=5).json()
    assert len(r["nums"]) == 10, r
    total += sum(r["nums"])
print(total)   # 49319
```

**动态路线**：jadx 从 q46Activity 跟到 Vr/Xt——Frida 直接调 `Vr.nativeEnc/nativeSign` 拿现成参数对拍或转发；IDA 路线看 KSA 循环前的初始化代码：标准 RC4 是 `S[i]=i` 递增赋值，这里是 memcpy 查表加载——顺着那张表 xref 就找到 KSA_INIT，再顺 PRGA 出口找 XMASK。

**坑位提醒**：两层魔改缺一不可——只还原初排、忘掉输出掩码（或反之），结果照样对不上；`Yw.FAKE_KEY = Fatdog_vile` 一字之差（命中即 403）；`strings libjade.so` 默认看不见真标记，要 `-el`。答案：加和 `49319`；flag `FLAG_18_KL9{dipper_veil_lifted}`


---


### KL10：万象归一（流沙河收官 · 魔改 SHA256 变体 + 魔改 AES 综合卷）

**考点**：libonyx.so 双层叠加签名 `sign = hex(魔改AES-128-ECB(aes_key, 魔改SHA256("page=N&ts=T")))`。
第一层 SHA256 变体：K 表/压缩轮与标准完全一致（认骨架看 K 表开头 428a2f98），但①初始 IV 整组替换为 `sha256("Fatdog_eclipse|iv")`、②消息填充边界从标准 56 前移到 48（长度域写进 48..55，等效多补一轮压缩）。
第二层 AES-128：S 盒/行移位/轮结构全标准（认骨架看 S 盒开头 637c777b），但 MixColumns 系数 `{2,3}` 对调为 `{3,2}`。
密钥派生：`iv = sha256(标记|"iv")` 全 32 字节、`aes_key = sha256(标记|"key")[:16]`。真标记 `Fatdog_eclipse` 以 UTF-16 码元藏匿；明文的 `Fatdog_ellipse` 是一字之差诱饵（命中即 403）；`m5_decoy_seal` 返回假密文。

**协议**：POST https://…:8443/api/kl10（表单 page/ts/sign）。服务端用同款双层实现重算并 compare_digest——哈希不可逆，所以这是"重算比对"而非"解密核对"。

对拍样例：page=1&ts=1787013761 →
digest（第一层输出）= b2daed7e2bf7e6b08a764db94bbfbc4120da4224e372ac7f6a37939699c8750c
sign（第二层输出）= df262f07d823c7b530cb65d54a4aa6a2a5f08d2e442b08ee493b434eac64ecc0

（生成器 gen_kl10.py 自测三件套：标准路径与 hashlib 逐字节对拍、FIPS-197 官方向量、魔改两层各自偏离标准；C 主机编译与 Python 三方一致。）

**静态路线（Python 全复刻，先 python server.py）**

```python
import hashlib, time, requests
from gen_kl10 import sha_var, pad, ecb_encrypt

MARKER = b"Fatdog_eclipse"
iv_words = [int.from_bytes(hashlib.sha256(MARKER + b"|iv").digest()[4*i:4*i+4], "big")
            for i in range(8)]
aes_key = hashlib.sha256(MARKER + b"|key").digest()[:16]

total = 0
for page in range(1, 101):
    ts   = int(time.time())
    dg   = sha_var(f"page={page}&ts={ts}".encode(), iv_words, boundary=48)  # 魔改层一
    sign = ecb_encrypt(aes_key, pad(dg), mix_swap=True).hex()               # 魔改层二
    r = requests.post("https://127.0.0.1:8443/api/kl10",
                      data={"page": page, "ts": ts, "sign": sign},
                      verify="certs/ca.crt", timeout=5).json()
    assert len(r["nums"]) == 10, r
    total += sum(r["nums"])
print(total)   # 51136
```

手写同款要点：SHA256 只动两处——h[] 初值换成派生 IV、padding 的 `while len%64 != 56` 改成 `!= 48`；AES 只动一处——列混合里乘 2 与乘 3 的位置互换。其余一个字节都不要碰。

**动态路线**：jadx 从 r47Activity 跟到 Ws/Zx——nativeDigest/nativeSign 分层暴露正好给 Frida 观察中间值：先 hook nativeDigest 看"不是 hashlib 的摘要"，dump so 里 m5_sha_variant 装载完的 h[8] 即见换血 IV；再看 nativeSign 入口的 digest 与出口 sign，偏移定位 m5_mix 里 gmul(…,3)/gmul(…,2) 的调用顺序即实锤系数对调。

**坑位提醒**：两层改动点都要找齐，漏一层签名就对不上；`Zw.FAKE_KEY = Fatdog_ellipse` 一字之差（命中即 403）；`strings libonyx.so` 默认看不见真标记，要 `-el`。答案：加和 `51136`；flag `FLAG_18_KL10{myriad_as_one}`。流沙河五连关至此全部通关。


---


## 天地秘境 · 幽冥海（KL11-15）


> 幽冥海六关统一讲一件事：**patch 是一门手艺，而手艺会被反 patch 技术针对**。KL11 教最原始的静态 patch（nop 一条指令）；KL12 教用 Frida 做"动态 patch"（改返回值）；KL13 开始上 CRC 自校验，逼你 hook 或连基线一起改；KL14 把校验拆到三个 so 交叉调用；KL15 是三阶段递进算法的综合卷。每关的提交机制各不相同，先看题面再动手。

### KL11：偷梁换柱（幽冥海 · 静态 patch 入门）

**考点**：SO patch 最小靶场——在 IDA 里找到比较指令并 nop 掉。`libhelix.so`（桥 `Tu`）导出两个 C 函数：

```c
int guard(int input) { return input == 0x46415444 ? 1 : 0; }   // "FADD"
int answer(void)     { return 0x46415444 ^ 0x1337; }           // 0x46414773
```

**解法（静态 patch，本关主解）**：
1. IDA/Ghidra 打开 `libhelix.so`，定位导出 `guard`；
2. 认 ARM64 指令骨架：`CMP W0, #0x46415444` + `B.EQ loc_xxx`（相等才跳到 `return 1`）；
3. 把 `B.EQ` 改 NOP（ARM64 NOP = `1F 20 03 D5`）或改成无条件 `B`，重打包安装；
4. App 内点「重新检测 guard」，`guard(0)=1` 后输入框解锁；
5. 提交 `answer()` 的返回值。

**答案**：`answer()` = `0x46415444 ^ 0x1337` = **1178683251**（十进制），flag `FLAG_18_KL11{nop_the_guard}`。

**备选（Frida）**：不改字节，hook 导出符号或 Java 桥都行：

```javascript
// hook native 符号
Java.perform(function(){
  var g = Module.findExportByName('libhelix.so','guard');
  Interceptor.attach(g, { onLeave: function(r){ r.replace(ptr(1)); } });
});
```

**坑位提醒**：so 里躺着真标记 `Fatdog_tamper`（UTF-16 码元数组）与一字之差的诱饵 `Fatdog_temper`（tamper→temper）；导出的 `m10_*` 全是无意义诱饵。`answer()` 在 IDA 里就是一个立即数返回，别去逆向复杂逻辑。

### KL12：移花接木（幽冥海 · Frida 动态 patch 入门）

**考点**：同一个"返回值校验"，静态 patch 要动多处、Frida 一行 hook 就过——这正是动态 patch 的教学价值。`libkraken.so`（桥 `Uk`）：

```c
#define SEAL_MAGIC 0x1337CAFE
#define XOR_KEY    0x0000BEEF
int seal(void) { return SEAL_MAGIC ^ XOR_KEY; }   // 未 hook 时 = 0x1337C411（错值）
int check(int v){ return v == SEAL_MAGIC ? 1 : 0; }
```

`seal()` 故意返回错误值 `0x1337C411`（真值异或 `0xBEEF`），`check(seal())` 恒为 0；提交按钮会先跑一次 `nativeCheck(nativeSeal())`，不过 1 就不让你提交。

**解法（Frida 主解）**——把 `seal` 的返回值换成真值：

```javascript
Java.perform(function(){
  var seal = Module.findExportByName('libkraken.so','seal');
  Interceptor.attach(seal, { onLeave: function(r){ r.replace(ptr(0x1337CAFE)); } });
});
```

**答案**：提交 `seal()` 的返回值，三种格式均可：`0x1337cafe` / `1337cafe` / `322423550`；flag `FLAG_18_KL12{hook_the_seal}`。

**坑位提醒**：静态 patch 也能过但要改多处（`seal` 的立即数 + `check` 的比较点），说明"返回值校验"这种模型天然偏向动态方案。真标记 `Fatdog_forge`，诱饵 `Fatdog_forgo`（forge→forgo，一字之差）。

### KL13：声东击西（幽冥海 · 反 patch：真实代码段 CRC 自校验）

**考点**：patch 任何指令都会被 CRC 抓住。`libmantis.so`（桥 `Ap`）的 `guard()` 开头对**自己函数起始 256 字节的机器码**重算 CRC-32，与编译期烘焙进 `.rodata` 的基线 `kGuardCrcBaseline`（arm64 `0xb35d0aad` / armeabi-v7a `0xad042dd3`，由 `tools/gen_code_crc_baselines.py` 按 ABI 生成）比对；不一致直接 `return 0`。所以静态改 `guard`/`check` 代码段字节 = 必死，除非把基线一起改成 patch 后的 CRC。

**三条解法**：
1. **Frida（最简单）**：不改字节就测不到 CRC。hook `check` 强制返回 1：

```javascript
Java.perform(function(){
  var chk = Module.findExportByName('libmantis.so','check');
  Interceptor.attach(chk, { onLeave: function(r){ r.replace(ptr(1)); } });
});
```

2. **patch + 同步基线**：IDA 改字节后，用同一 CRC 算法（多项式 `0xEDB88320`，与 `zlib.crc32` 一致）对 guard 起始 256 字节重算，把结果写回 `.rodata` 的 `kGuardCrcBaseline`。教学价值最高，也是最容易翻车的一条路。
3. **完整复刻（Python）**：`guard(MAGIC)` 的判定就是 `input == 0xCAFEBABE`，绕开 CRC 后答案显而易见。

**答案**：`guard(0xCAFEBABE)` 的返回值 = **1**（CRC 通过 + MAGIC 匹配才算对），flag `FLAG_18_KL13{crc_cannot_protect}`。

**坑位提醒**：真标记 `Fatdog_guard` 与诱饵 `Fatdog_gourd`（guard→gourd）；CRC 基线**不是**运行时用同一份常量自算，而是编译期对真实产物烘焙的指纹，所以只 hook `verify_crc` 之外的地方没用——要么 hook 出口，要么改基线。

### KL14：偷天换日（幽冥海 · 三 so 交叉验证）

**考点**：把"一道校验"拆到三个 so 互相 dlsym 调用——patch 任一 so 的计算逻辑或导出符号，最终 hash 都对不上。`libnebula.so`、`libopera.so`、`libplume.so` 通过同一个 Java 桥 `Zn` 暴露，SEED = `20280419`：

- `libnebula.so`：`Zn.nativePartA()` → `A = SEED ^ 0xAA = 20280521`；另导出 `nativeXor` 供跨 so 调用；
- `libopera.so`：`m13b_get_digest_B()` → `B = SEED ^ 0xBB = 20280536`；
- `libplume.so`：`Zn.nativeCombineFromC()` 用 dlsym 把 A、B 取回来，**A‖B 各按 4 字节大端拼成 8 字节**做 SHA-256，hex 就是最终答案。

注意：三份 so 里还埋着 `compute_digest()` 这类"sha256 取前 8 hex"的中间函数与 `m13*_decoy_seal/fold/spin` 诱饵导出，全都不在 UI 校验路径上，别被带偏——UI 只比对 `nativeCombineFromC()` 的返回值。

**静态复刻（Python）**：

```python
import hashlib
SEED = 20280419
A = SEED ^ 0xAA          # 20280521
B = SEED ^ 0xBB          # 20280536
ans = hashlib.sha256(A.to_bytes(4,'big') + B.to_bytes(4,'big')).hexdigest()
print(ans)
```

**答案**：`55c39be2c7837ce910ec5d151ffd37df30bf8b27e4e06a0255e614a29c2d2eb0`（64 位 hex），flag `FLAG_18_KL14{mesh_of_three}`。

**动态路线**：Frida 逐个 hook `nativePartA` / `m13b_get_digest_B`（或直接 hook `nativeCombineFromC` 的出口）拿返回值对拍；unidbg 需把三个 so 一起加载并处理 dlsym 依赖。真标记 `Fatdog_mesh`，诱饵 `Fatdog_mash`（mesh→mash）。

### KL15：万法归宗（幽冥海收官 · 三阶段递进谜题）

**考点**：不是"一个 guard 一个 answer"，而是 `computeA() → computeB(a) → computeC(a,b) → verify(a,b,c)` 三段依赖算法，三值全对才通关。`libshale.so`（桥 `Am`），SEED = `20280426`、MAGIC = `0xDEADCAFE`、XOR_K = `0xBEEF`、密钥字节 `KX = 5E 3A 7D 1F 92 64 A8 C0`：

```c
// A：seed^MAGIC → 循环左移 13 → ^XOR_K → *0x9E3779B9 + 0x12345678 → 逐字节 ^KX[0..3]（内存序）
// B：CRC32(A 的 4 字节大端) ^ (KX[0]|KX[1]<<8|KX[2]<<16|KX[3]<<24)
// C：SHA256(A_be ‖ B_be) 取前 4 字节大端
```

**Python 全复刻**：

```python
import hashlib, zlib
MASK = 0xFFFFFFFF
SEED, MAGIC, XOR_K = 20280426, 0xDEADCAFE, 0xBEEF
KX = bytes([0x5E,0x3A,0x7D,0x1F,0x92,0x64,0xA8,0xC0])
kx = int.from_bytes(KX[:4], 'little')

v = (SEED ^ MAGIC) & MASK
v = ((v << 13) | (v >> 19)) & MASK
v ^= XOR_K
v = (v * 0x9E3779B9 + 0x12345678) & MASK
A = (v ^ kx) & MASK                       # 3269614058

B = (zlib.crc32(A.to_bytes(4,'big')) & MASK) ^ kx   # 1673341562
C = int.from_bytes(hashlib.sha256(A.to_bytes(4,'big') + B.to_bytes(4,'big')).digest()[:4], 'big')  # 1632186679
print(A, B, C)
```

**答案**（三个十进制整数，全对才过）：
- `A = 3269614058`
- `B = 1673341562`
- `C = 1632186679`

flag `FLAG_18_KL15{all_methods_converge}`。

**动态路线**：Frida hook `Am.nativeComputeA/B/C` 出口拿值对拍，或按 A→B→C 依赖静态复刻（本地 UI 只收三值，`nativeVerify` 全对才返回 1）。`nativeGuard` 叠 ptrace 反调试，`nativeGuard`/`nativeVerify` 都会走真实代码段 CRC：基线由 `tools/gen_shale_crc_baseline.py` 从 NDK 产物按 ABI 烘焙进 `shale_crc_baseline.h`，静态 patch 窗口内指令会返回 -2。真标记 `Fatdog_pact`，诱饵 `Fatdog_packed`。

## 天地秘境 · 太玄之初（KL16-20、KKL1-5）


### KL16：破壳新生（一代壳 · 分片动态加载 + 标准 AES 取数）

**考点**：梆梆一代壳的核心思想——DEX 整体加密、壳在加载时把分片"悄悄"拼回内存（不落盘）。本题把它具象成"标记拆两段密文，JNI_OnLoad 两阶段动态还原"，还原出的真标记再派生标准 AES/HMAC 密钥去给网络请求加签取数。难点不在算法（标准 AES-128-ECB，轮常量未魔改），而在"标记必须让 so 真正跑起来才完整"。

> 标记：真 `Fatdog_unveil`；明文诱饵 `Fatdog_unveils`（一字之差，strings 可见，用错即 403）。

#### 静态路线（IDA 逆 JNI_OnLoad）

**Step 1：定位壳入口**
1. jadx 看 `gladeActivity` → 它走的是网络求和 UI（`Va.fetchPage` → `GET /api/kl16`），不是本地比对。
2. `Va.java` 里 `System.loadLibrary("ash")` → 核心在 `libash.so`。
3. `gladeActivity` 的提示已点明：DEX 是死的，字符串里只有形近诱饵，真标记要"动态起来"才完整。

**Step 2：逆两段密文还原标记**
`libash.so` 的 `JNI_OnLoad` 调 `ash_load_stage1()` + `ash_load_stage2()`：
- 阶段1：`ENC_A[7]` 逐字节 `ror3` 后 `XOR KEYA` → 还原 `"Fatdog_"`
- 阶段2：`ENC_B[6]` 逐字节 `ror1` 后 `XOR KEYB` → 还原 `"unveil"`
- 两段拼起 = 真标记 `Fatdog_unveil`

常量（.rodata，注意是 `ror` 不是 `rol`，加密时 `rol` 藏入）：
```
KEYA = {0x5A, 0x3C, 0x21, 0x7E}
KEYB = {0x7E, 0x21, 0x3C, 0x5A}
ENC_A = {0xe0, 0xea, 0xaa, 0xd0, 0xa9, 0xda, 0xf3}   # ror3+XOR KEYA -> "Fatdog_"
ENC_B = {0x16, 0x9e, 0x94, 0x7e, 0x2e, 0x9a}       # ror1+XOR KEYB -> "unveil"
```

**Step 3：派生密钥 + 复刻请求**
标记运行时派生（先跑完两段加载才有）：
```
aes_key = SHA256(标记 + "|aes")[:16]
mac     = SHA256(标记 + "|mac")         # 完整 32 字节
```
请求载荷 `page=N&ts=T` 零填充到 32 字节，标准 AES-128-ECB 加密得 `enc`（hex），`sign = HMAC-SHA256(mac, enc)`。**AES 是标准轮常量，没有换血**（这是与 KL6 的本质区别）。

#### 动态路线（Frida，最快）
直接在 `JNI_OnLoad` 之后读还原好的标记，或 hook 导出函数：
```javascript
Java.perform(function () {
    var Va = Java.use('com.fatdog.reverse.Va');
    console.log('marker =', Va.nativeMarker());   // "Fatdog_unveil"
    console.log('decoy  =', Va.nativeDecoy());     // "Fatdog_unveils"
});
```
也可以直接 hook `nativeEnc`/`nativeSign` 拿现成的 enc/sign 去发包，省去复刻。

#### 脱壳路线（内存 dump：把壳拼好的明文从内存抠出来）

一代壳的精髓就是"启动时才把加密内容还原进内存"，所以**最正统的打法就是脱壳——在还原完成、被使用之前的瞬间把内存里的明文抠出来**。本关的"加密内容"不是真实 DEX 文件，而是两阶段拼回的标记 `Fatdog_unveil`，它藏在 `libash.so` 的 `.bss` 段（`static char g_mark[64]`，由 `JNI_OnLoad` → `ash_load_stage1` / `ash_load_stage2` 在运行时填进去）。这带来一个关键现象：**`strings libash.so` 静态扫只能看到诱饵字面量 `Fatdog_unveils`（编译期写死的 `DECOY_MARK`），真标记 `Fatdog_unveil` 是运行时才出现的明文**——这正是脱壳能拿到、静态分析拿不到的东西。

**方法 A：frida 直接读还原后的标记（最省事，等价于脱壳成品）**
```javascript
Java.perform(function () {
    var Va = Java.use('com.fatdog.reverse.Va');
    // JNI_OnLoad 早就在 native 层跑完了两段加载，这里直接取成品
    console.log('[dump] marker =', Va.nativeMarker());
});
```

**方法 B：纯 native 抠 `g_mark` 缓冲区（不依赖 Java 层）**
```javascript
var base = Module.findBaseAddress('libash.so');
var off  = 0xXXXX;   // g_mark 相对 so 基址的偏移：在 IDA/Ghidra 里看 .bss 中 g_mark 符号地址减去 so 基址
var len  = 13;       // strlen("Fatdog_unveil")
console.log('[dump]', base.add(off).readUtf8String(len));
```

**方法 C：扫 `/proc/<pid>/maps` + 读 `/proc/<pid>/mem` 抠 so 的 rw 段**
```bash
pid=$(pidof com.fatdog.reverse)        # 或 ps | grep fatdog
grep libash.so /proc/$pid/maps         # 找 rw-p 那一行（data/bss）
python3 - <<'PY'
import re
pid = <填 pid>
with open(f'/proc/{pid}/maps') as f: maps=f.read()
for line in maps.splitlines():
    if 'libash.so' in line and 'rw-p' in line:
        a,b = [int(x,16) for x in line.split()[0].split('-')]
        with open(f'/proc/{pid}/mem','rb') as mem:
            mem.seek(a); buf=mem.read(b-a)
        for m in re.findall(rb'Fatdog_[a-z]{4,8}', buf):
            print('found', m)          # 跑完 JNI_OnLoad 后 Fatdog_unveil 会出现（诱饵 Fatdog_unveils 也在）
PY
```
两条 `Fatdog_*` 都会出来，真标记靠长度（13）和上下文（`unveil` 不是 `unveils`）区分。

**方法 D：知识迁移——真实一代壳怎么 dump DEX（本关用不到，但 KL17–KL20 用得上）**
本关没有"加密 DEX 文件"（标记走 native、答案走网络求和），所以 DEX-dump 拿不到 flag；但思路完全通用，先在这里把"内存抠取"的手感练熟：
- hook `libart.so` 的 `OpenMemory` / `DexFile::DexFile` 构造 / `InMemoryDexClassLoader` 构造，在解密完成、加载前的那一刻 dump 出 `dex\n035` 魔数开头的字节；
- 或上 **frida-fart / FART**，自动在 `openDexFile` 时机 dump 并修复 `dexHeader` 的 `fileSize` / `classDefsSize` 等被壳改坏的字段；
- dump 出来的 DEX 头字段常被壳改坏，需 `dexrepair` / 010 Editor 模板修 `mapOff` / `stringIdsSize` 再进 jadx / gda。

> 小结：本关三种打法对应三种思维——**静态逆**（逆 `JNI_OnLoad` 还原算法）、**动态 hook**（Frida 直接读成品）、**脱壳 dump**（把还原后的明文从内存抠出来）。后两者正是针对"真标记不在静态字符串"这一核心设定：静态 `strings` 只有诱饵，内存里才有真标记。

#### 完整 Python 复刻（还原标记 → 取数 → 求和）
```python
import hashlib, hmac, random, time, json, ssl, urllib.request

KEYA = bytes([0x5A,0x3C,0x21,0x7E])
KEYB = bytes([0x7E,0x21,0x3C,0x5A])
ENC_A = bytes([0xe0,0xea,0xaa,0xd0,0xa9,0xda,0xf3])
ENC_B = bytes([0x16,0x9e,0x94,0x7e,0x2e,0x9a])

def ror(b,n): return ((b >> n) | (b << (8-n))) & 0xFF
marker = b''
for i in range(len(ENC_A)): marker += bytes([ror(ENC_A[i],3) ^ KEYA[i%4]])
for i in range(len(ENC_B)): marker += bytes([ror(ENC_B[i],1) ^ KEYB[i%4]])
marker = marker.decode()
assert marker == 'Fatdog_unveil', marker

aes_key = hashlib.sha256((marker+'|aes').encode()).digest()[:16]
mac     = hashlib.sha256((marker+'|mac').encode()).digest()

# 标准 AES-128-ECB
SBOX=[0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
RCON=[0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
def xt(a): return ((a<<1)^0x1B)&0xFF if a&0x80 else (a<<1)
def gmul(a,b):
    r=0
    while b:
        if b&1: r^=a
        a=xt(a); b>>=1
    return r
def key_expand(key):
    rk=[list(key)]
    for i in range(1,11):
        p=rk[-1]; t=[SBOX[p[13]],SBOX[p[14]],SBOX[p[15]],SBOX[p[12]]]; t[0]^=RCON[i-1]
        c=[0]*16
        for j in range(4): c[j]=p[j]^t[j]
        for j in range(4,16): c[j]=p[j]^c[j-4]
        rk.append(c)
    return rk
def shift(s):
    s[1],s[5],s[9],s[13]=s[5],s[9],s[13],s[1]
    s[2],s[6],s[10],s[14]=s[10],s[14],s[2],s[6]
    s[3],s[7],s[11],s[15]=s[15],s[3],s[7],s[11]
def enc_block(pt,rk):
    s=list(pt)
    def ark(k):
        for i in range(16): s[i]^=k[i]
    ark(rk[0])
    for r in range(1,10):
        s=[SBOX[x] for x in s]; shift(s)
        for c in range(4):
            a0,a1,a2,a3=s[4*c],s[4*c+1],s[4*c+2],s[4*c+3]
            s[4*c]=gmul(a0,2)^gmul(a1,3)^a2^a3
            s[4*c+1]=a0^gmul(a1,2)^gmul(a2,3)^a3
            s[4*c+2]=a0^a1^gmul(a2,2)^gmul(a3,3)
            s[4*c+3]=gmul(a0,3)^a1^a2^gmul(a3,2)
        ark(rk[r])
    s=[SBOX[x] for x in s]; shift(s); ark(rk[10])
    return bytes(s)
rk=key_expand(list(aes_key))
def build(page,ts):
    payload=("page=%d&ts=%d"%(page,ts)).encode()+b"\x00"*(32-len("page=%d&ts=%d"%(page,ts)))
    ct=b"".join(enc_block(payload[i:i+16],rk) for i in range(0,32,16))
    enc=ct.hex()
    sign=hmac.new(mac,enc.encode(),hashlib.sha256).hexdigest()
    return enc,sign

# 离线取数（与服务端 SEED_KL16=20260116 完全一致）
SEED=20260116; rng=random.Random(SEED)
total=sum(rng.randint(1,100) for _ in range(1000))
print("SUM =", total)
print("SUM_HASH =", hashlib.sha256(str(total).encode()).hexdigest())
# 实战联网：enc,sign = build(page,ts) 后带去 GET /api/kl16?page=&ts=&enc=&sign=
```
> 联网取数只需把 `build(page,ts)` 的 enc/sign 带去 `GET /api/kl16?page=&ts=&enc=&sign=`；上面的离线分支用于不依赖服务端的自测，结果应与线上一致。

#### 服务端取数结果（离线可复现）
- `SEED_KL16 = 20260116`，`random.Random(SEED)` 生成 100×10 个 1–100 整数
- **总和 = 51495**
- **SUM_HASH = `ec806594f8a8ea937168d438694b994cfe6f5fc94e57c4868032e61f50bed933`**

把 `51495` 填进 `gladeActivity` 的输入框 → `sha256("51495")==SUM_HASH` → 放行，弹出 `FLAG_18_KL16{husk_shed}`。

#### 坑位提醒
1. **真标记不在静态字符串**：`Fatdog_unveil` 只出现在 so 注释里，编译后不在二进制字符串表；`Fatdog_unveils` 才是明文字面量（诱饵）。想拿真标记必须让 `JNI_OnLoad` 跑完两段加载。
2. **AES 是标准轮常量**：别像 KL6 那样去找"换血"的 Rcon——本关 RCON 是 `0x01,0x02,...,0x1b,0x36` 标准表，魔改点不在这。
3. **两段用不同密钥/旋转**：阶段1 `ror3+XOR KEYA`，阶段2 `ror1+XOR KEYB`，拼错一段标记就对不上，进而 aes/mac 钥全错。
4. **诱饵即 403**：用 `Fatdog_unveils` 派生密钥，服务端 `_kl16_try` 命中 decoy 分支直接 403。
5. **载荷零填充 32 字节**：`page=N&ts=T` 不足 32 字节要补 `\x00`，AES-ECB 分两块；服务端按 `\x00` 截断解析。

**flag**：`FLAG_18_KL16{husk_shed}`

---

### KL17：金蝉脱壳（二代壳·360 加固保类抽取）

**考点**：识别「类抽取」范式——真标记被拆成 4 段散布在 so 的不同函数 / rodata 段，
只有 stub「加载」（`JNI_OnLoad`）时才把各段回填拼回完整标记；拿到标记后派生
HMAC 钥匙，带签请求取 100 页数字求和。

本关与 KL16 的区别：KL16 是一代壳「整体加密、分片加载」（两段 + AES 加密请求体），
KL17 是二代壳「类抽取、分片回填」（四段 + 仅 HMAC 签名，不再 AES 加密请求体）。
算法都是**标准** SHA-256 / HMAC-SHA256（前三关不魔改），难度全在前置的「回填」。

- 真标记：`Fatdog_reclaim`（14 字节）
- 明文诱饵：`Fatdog_reclaims`（多一个 s，`strings` 一眼可见）
- so：`libviola.so`；JNI 桥：`Ek`；活动页：`hollowActivity`
- 请求：`GET /api/kl17?page=N&ts=T&sign=<hex>`

---

#### 路线一：静态逆 `JNI_OnLoad`（还原四段 → 拼回标记）

`libviola.so` 里有四个「回填函数」，每个只负责还原一段（模拟被抽走的方法体各自回填）：

```c
static void fill_seg0(char *out, int *len) {   /* 段0 = "Fatd" */
    for (i = 0; i < 4; i++)
        out[i] = (char)ror8(ENC_0[i] ^ KEY_0[i % 4], 1);
    *len = 4;
}
static void fill_seg1(char *out, int *len) {   /* 段1 = "og_r"，rot=3 */
static void fill_seg2(char *out, int *len) {   /* 段2 = "ecl" ，rot=2 */
static void fill_seg3(char *out, int *len) {   /* 段3 = "aim" ，rot=4 */

static void refill_marker(void) {              /* stub「加载」时调用 */
    int off = 0, n;
    fill_seg0(g_mark + off, &n); off += n;
    fill_seg1(g_mark + off, &n); off += n;
    fill_seg2(g_mark + off, &n); off += n;
    fill_seg3(g_mark + off, &n); off += n;
    g_mark_len = off; g_mark[off] = 0;
}
```

四段的密文与参数（IDA 里在 `.rodata` / 立即数中找，注意它们是**分散**在不同函数里的）：

| 段 | 密文 ENC_i | 异或 KEY_i | 循环右移 rot | 还原后 |
|---|---|---|---|---|
| 0 | `b0 98 c9 b6` | `3C 5A 21 7E` | 1 | `Fatd` |
| 1 | `21 07 84 b2` | `5A 3C 7E 21` | 3 | `og_r` |
| 2 | `b4 f3 8d` | `21 7E 3C` | 2 | `ecl` |
| 3 | `68 b7 8c` | `7E 21 5A` | 4 | `aim` |

还原公式（先异或再循环右移）：

```python
def ror8(b, n): return ((b >> n) | (b << (8 - n))) & 0xFF
ch = ror8(ENC[i] ^ KEY[i % 4], rot)
```

四段顺序拼接即 `Fatdog_reclaim`。**坑**：`strings` 里能看到的 `Fatdog_reclaims` 是诱饵
（编译期字面量），真标记只在运行时才存在于 `g_mark`（`.bss`），静态扫不到。

---

#### 路线二：动态——Frida 直读 / 内存 dump（等价于脱壳）

真标记在 `.bss` 的 `static char g_mark[64]`，`JNI_OnLoad` 回填后才有内容。

**方法 A（最省事）**：直接调导出函数拿成品，再去复刻签名：

```javascript
Java.perform(function () {
    var Ek = Java.use('com.fatdog.reverse.Ek');
    console.log('marker:', Ek.nativeMarker());   // Fatdog_reclaim
    console.log('decoy :', Ek.nativeDecoy());    // Fatdog_reclaims
    console.log('sign  :', Ek.nativeSign(1, Java.use('java.lang.System').currentTimeMillis() / 1000));
});
```

**方法 B（抠 native 内存）**：读 `libviola.so` 基址 + `g_mark` 偏移处的 14 字节。

```javascript
var base = Module.findBaseAddress('libviola.so');
// g_mark 偏移需自己在 IDA/Ghidra 里看 .bss 符号地址减 so 基址
console.log(hexdump(base.add(0xXXXX), { length: 16 }));
```

**方法 C（经典手工 dump）**：扫 `/proc/<pid>/maps` 找 `libviola.so` 的 `rw-p` 段，
读 `/proc/<pid>/mem` 抠出 `.bss`，grep `Fatdog_`（真诱饵都会出现，靠长度 14 /
`reclaim` ≠ `reclaims` 区分）。

**方法 D（知识迁移：真实二代壳怎么脱）**：360 加固保这类类抽取壳，方法体在
`ClassLinker::DefineClass` 前后由 native 回填，脱壳要点是**主动调用触发还原**——
遍历 `ClassLoader` 加载所有类并主动调用方法（FART / youpk 的思路），在回填完成后的
「还原点」dump 出完整方法体，再用 dexfixer 把抽空的方法体回填进 DEX，最后 jadx 读。
本关把这段真实流程压缩成「四个 fill 函数 + 一个 refill」，回填的正是签名钥匙的原料。

---

#### 完整 Python 复刻（还原标记 → 派生钥匙 → 取数 → 求和）

```python
import hashlib, hmac, random, time, urllib.parse, urllib.request

# ---- 1. 四段回填还原真标记（静态逆 JNI_OnLoad 的结果）----
def ror8(b, n): return ((b >> n) | (b << (8 - n))) & 0xFF

SEGS = [
    (bytes([0xb0, 0x98, 0xc9, 0xb6]), bytes([0x3C, 0x5A, 0x21, 0x7E]), 1),
    (bytes([0x21, 0x07, 0x84, 0xb2]), bytes([0x5A, 0x3C, 0x7E, 0x21]), 3),
    (bytes([0xb4, 0xf3, 0x8d]),       bytes([0x21, 0x7E, 0x3C]),       2),
    (bytes([0x68, 0xb7, 0x8c]),       bytes([0x7E, 0x21, 0x5A]),       4),
]
mark = b"".join(bytes(ror8(e[i] ^ k[i % len(k)], r) for i in range(len(e)))
                for e, k, r in SEGS)
print("mark =", mark.decode())          # Fatdog_reclaim

# ---- 2. 派生 HMAC 钥匙并对请求签名 ----
KEY = hashlib.sha256(mark + b"kl17").digest()[:32]
print("KEY  =", KEY.hex())              # 5ca6f55c41e6e3a7...a1af21c39f5

def sign(page, ts):
    return hmac.new(KEY, ("page=%d&ts=%d" % (page, ts)).encode(),
                    hashlib.sha256).hexdigest()

# ---- 3. 100 页取数求和（在线）----
def fetch(page):
    ts = int(time.time())
    q = urllib.parse.urlencode({"page": page, "ts": ts, "sign": sign(page, ts)})
    with urllib.request.urlopen("https://127.0.0.1:8443/api/kl17?" + q, timeout=5) as r:
        import json
        return json.loads(r.read().decode())["nums"]

total = 0
for p in range(1, 101):
    total += sum(fetch(p))
print("sum =", total)                   # 49227

# ---- 3'. 离线等价（服务端 SEED 固定，本地可复算）----
rng = random.Random(20260117)
offline = sum(rng.randint(1, 100) for _ in range(1000))
print("offline sum =", offline)         # 49227

# ---- 4. 提交：sha256(str(sum)) ----
print("SUM_HASH =", hashlib.sha256(str(total).encode()).hexdigest())
```

**服务端取数结果**

- `SEED_KL17 = 20260117`，100 页 × 10 个 → 1000 个数
- 加和 **49227**
- `SUM_HASH = cfb56f84db84b46d25b59a25b377c141c240492dea7520b65dc8a622ca5143b5`

---

#### 坑位提醒

1. **真标记不在静态字符串里**——`strings libviola.so` 只能翻到诱饵 `Fatdog_reclaims`；
   真标记在 `.bss` 的 `g_mark`，`JNI_OnLoad` 回填后才存在（静态派必须自己逆四段）。
2. **四段参数各不相同**——rot 依次 1/3/2/4，四个 KEY 也不同；拿一个 KEY 去解四段必然错。
3. **每段 KEY 按 `i % len(KEY)` 循环取**——段 2/3 的 KEY 只有 3 字节，别当成 4 字节算。
4. **诱饵即 403**——用 `Fatdog_reclaims` 派生钥匙签名，服务端会命中诱饵分支返回 403
   （而不是返回空数组），别误判成"签名算法写错了"。
5. **签名对象是 `page=N&ts=T` 原文**——不是 URL 编码后的串，也不含 `sign` 自身；
   `ts` 有 600 秒时间窗，过期要重新取时间戳。
6. **本关没有 AES**——和 KL16 不同，请求体是明文 `page`/`ts`，只额外带 `sign`。

**flag**：`FLAG_18_KL17{class_refilled}`

---

### KL18：乾坤迷阵（二代壳·梆梆方法抽取）

**考点**：识别「方法抽取」范式——真标记的**每个字节**都被当作一条被抽走的「方法体」，
运行时缓冲区先被 nop 填满，只有走到**还原点**时才逐条填回，且后一条依赖前一条。
拿到标记后派生 HMAC 钥匙，带签请求取 100 页数字求和。

**与 KL17 的递进差异（本关题眼）**

| | KL17 类抽取 | KL18 方法抽取 |
|---|---|---|
| 粒度 | 4 个整段 | 14 个单字节 |
| 还原时机 | `JNI_OnLoad`（加载时）一次性回填 | 加载时**不还原**，必须走还原点才逐条填回 |
| 加载后 dump | 已是完整标记 | 全是 nop 占位符 |

所以本关**光把 so 加载起来没用**——必须主动触发还原（调 `nativeMarker()` 或发起一次签名请求），
这正是真实二代壳「主动调用触发还原」（FART / youpk）的教学对应。

- 真标记：`Fatdog_reweave`（14 字节）
- 明文诱饵：`Fatdog_reweaves`（多一个 s，`strings` 一眼可见）
- so：`libblaze.so`；JNI 桥：`Fk`；活动页：`circuitActivity`
- 请求：`GET /api/kl18?page=N&ts=T&sign=<hex>`

---

#### 路线一：静态逆「还原点」（逐条解链）

`libblaze.so` 里只有一个抽走后的字节表和一个还原点函数：

```c
static const unsigned char EXTRACTED[14] = {
    0x21, 0xa3, 0xb8, 0xc6, 0xf4, 0x20, 0x69, 0x57,
    0xb4, 0xde, 0xe7, 0x1a, 0x50, 0x63
};
#define NOP_FILL 0xFF

static unsigned char bl_ks(int i) { return (0x5B + 41 * i) & 0xFF; }

/* 还原点：逐条填回（后一条依赖前一条） */
static void restore_point(int idx, unsigned char *prev) {
    unsigned char v = EXTRACTED[idx] ^ bl_ks(idx) ^ *prev;
    g_mark[idx] = (char)v;
    *prev = v;
}
static void restore_all(void) {
    unsigned char prev = 0x3C;
    for (int i = 0; i < 14; i++) restore_point(i, &prev);
    g_mark_len = 14; g_mark[14] = 0;
}
```

编码规则（逆过来就是解码）：

```
ks(i)     = (0x5B + 41*i) & 0xFF
EXTRACTED[i] = mark[i] ^ ks(i) ^ (i == 0 ? 0x3C : mark[i-1])
```

注意 `JNI_OnLoad` 里调的是 `nop_fill()`（把 64 字节全填 `0xFF`、长度置 0），
**不是** `restore_all()`——静态看控制流时别被"加载函数"骗了，真正的还原在 `restore_all()`，
而它只在 `nativeSign` / `nativeMarker` 内部被调用。

---

#### 路线二：动态——主动调用触发还原 / 内存 dump

本关的还原是**懒执行**的：不触发就永远是一坨 nop。

**方法 A：主动调用触发还原（对应 FART/youpk 思路，最省事）**

```javascript
Java.perform(function () {
    var Fk = Java.use('com.fatdog.reverse.Fk');
    // 调用即触发还原点；不调的话缓冲区里全是 nop
    console.log('marker:', Fk.nativeMarker());   // Fatdog_reweave
    console.log('decoy :', Fk.nativeDecoy());    // Fatdog_reweaves
    console.log('sign  :', Fk.nativeSign(1, Math.floor(Date.now() / 1000)));
});
```

**方法 B：对比还原前后的内存（体会"抽空→填回"）**

```javascript
var base = Module.findBaseAddress('libblaze.so');
// g_mark 偏移需自己在 IDA/Ghidra 里看 .bss 符号地址减 so 基址
var p = base.add(0xXXXX);
console.log('before:', hexdump(p, { length: 16 }));   // 全 ff = nop
Java.use('com.fatdog.reverse.Fk').nativeMarker();     // 触发还原点
console.log('after :', hexdump(p, { length: 16 }));   // Fatdog_reweave
```

**方法 C：抠 `/proc/<pid>/mem`**——扫 `maps` 找 `libblaze.so` 的 `rw-p` 段，
读 `/proc/<pid>/mem` 抠 `.bss`；**在触发还原之前 grep `Fatdog_` 是搜不到的**（只有 nop），
触发后才出现（真诱饵都在，靠长度 14 / `reweave` ≠ `reweaves` 区分）。

**方法 D：知识迁移——真实方法抽取壳怎么脱**
梆梆这类把方法体 nop/抽空、由 native 在调用前还原。脱壳要点同样是**主动调用**：
枚举 `ClassLoader` 加载所有类并主动 invoke 方法，逼壳把方法体还原回内存，
再在还原函数（`ClassLinker::LinkCode` / 自定义的 `restoreMethod`）上 hook dump，
最后用 dexfixer 把抽空的方法体**指令回填**进 DEX，jadx 才能读。
本关把这套流程压缩成「14 个字节 + 一个还原点」。

---

#### 完整 Python 复刻（还原点解链 → 派生钥匙 → 取数 → 求和）

```python
import hashlib, hmac, random, time, json, urllib.parse, urllib.request

# ---- 1. 走一遍还原点：逐字节解链（顺序依赖，不能跳着来）----
EXTRACTED = bytes([0x21,0xa3,0xb8,0xc6,0xf4,0x20,0x69,0x57,
                   0xb4,0xde,0xe7,0x1a,0x50,0x63])

def ks(i):
    return (0x5B + 41 * i) & 0xFF

mark = bytearray()
prev = 0x3C
for i, e in enumerate(EXTRACTED):
    v = e ^ ks(i) ^ prev
    mark.append(v)
    prev = v
print("mark =", bytes(mark).decode())     # Fatdog_reweave

# ---- 2. 派生 HMAC 钥匙并对请求签名 ----
KEY = hashlib.sha256(bytes(mark) + b"kl18").digest()[:32]
print("KEY  =", KEY.hex())                # 31597a2f0026eaf3...b73788dd1074d

def sign(page, ts):
    return hmac.new(KEY, ("page=%d&ts=%d" % (page, ts)).encode(),
                    hashlib.sha256).hexdigest()

# ---- 3. 100 页取数求和（在线）----
def fetch(page):
    ts = int(time.time())
    q = urllib.parse.urlencode({"page": page, "ts": ts, "sign": sign(page, ts)})
    with urllib.request.urlopen("https://127.0.0.1:8443/api/kl18?" + q, timeout=5) as r:
        return json.loads(r.read().decode())["nums"]

total = sum(sum(fetch(p)) for p in range(1, 101))
print("sum =", total)                     # 52453

# ---- 3'. 离线等价（服务端 SEED 固定，本地可复算）----
rng = random.Random(20260118)
print("offline sum =", sum(rng.randint(1, 100) for _ in range(1000)))   # 52453

# ---- 4. 提交：sha256(str(sum)) ----
print("SUM_HASH =", hashlib.sha256(str(total).encode()).hexdigest())
```

**服务端取数结果**

- `SEED_KL18 = 20260118`，100 页 × 10 个 → 1000 个数
- 加和 **52453**
- `SUM_HASH = 090ae9f92e3d8fe9f31887efbdd27dd992d61053f5922b225fad6479dd393b6b`

---

#### 坑位提醒

1. **加载 ≠ 还原**——`JNI_OnLoad` 只做 `nop_fill()`。只把 so 加载起来、或只 hook 库加载时机去 dump，
   拿到的是一坨 `0xFF`，什么都解不出来；必须触发还原点（调 `nativeMarker()` 或发一次签名请求）。
2. **顺序依赖**——解码是链式的：`mark[i]` 依赖 `mark[i-1]`（首字节的前导值是 `0x3C`）。
   想只解某一个字节、或并行乱序解，必然错。
3. **密钥流按索引走**——`ks(i) = (0x5B + 41*i) & 0xFF`，不是固定异或值，别当成单字节 XOR 去爆破。
4. **诱饵即 403**——用 `Fatdog_reweaves` 派生钥匙签名，服务端命中诱饵分支返回 403，
   不是"签名算法写错了"。
5. **签名对象是 `page=N&ts=T` 原文**——不含 `sign` 自身；`ts` 有 600 秒窗口，过期要重取时间戳。
6. **本关没有 AES，也没有反调试**——和 KL17 一样只额外带 `sign`；反调试要到 KL19 才登场。

**flag**：`FLAG_18_KL18{method_rewoven}`

---

### KL19：虚空造化（二代综合·指令抽取 + 反调试 + SO 自校验）

**考点**：这一关是二代壳的合卷——还原点外面裹了一层**哨兵**。
抽空→还原点填回的机制和 KL18 一样，但只有在哨兵"看不见有人盯着"时，
还原出来的标记才留得住；否则刚填回去就被抹平。所以正解顺序是：
**先让哨兵失明 → 再触发还原 → 拿标记 → 派生钥匙签名取数**。

| | KL18 方法抽取 | KL19 二代综合 |
|---|---|---|
| 还原点 | 逐字节链式填回 | 同样（参数不同） |
| 额外 | 无 | **反调试哨兵 + CRC 自校验** |
| 判定成立时 | — | 抹掉还原结果，签名失效 |

- 真标记：`Fatdog_rekindle`（15 字节）
- 明文诱饵：`Fatdog_rekindles`（多一个 s）
- so：`libbison.so`；JNI 桥：`Gk`；活动页：`emberActivity`
- 请求：`GET /api/kl19?page=N&ts=T&sign=<hex>`

---

#### 哨兵的五信号评分（含防误报设计）

```c
static int bs_guard_hits(void) {
    int h = 0;
    h += bs_hit_ptrace();                       /* ① ptrace(PTRACE_TRACEME) 失败且 errno==EPERM */
    h += bs_hit_tracerpid();                    /* ② /proc/self/status 的 TracerPid != 0       */
    h += bs_hit_frida_port();                   /* ③ connect 127.0.0.1:27042 成功             */
    h += bs_hit_maps();                         /* ④ maps 含 frida / gadget / gum             */
    h += (bs_crc32(EXTRACTED, 15) != 0x53006fcd);/* ⑤ SO 自校验：抽走的那张表被动过            */
    return h;
}
#define GUARD_THRESHOLD 2      /* 命中 ≥2 项才判定被调试 */
```

**为什么是"≥2 项"而不是"任一命中"**：单项信号存在误报（典型如某些 ROM 的 seccomp
直接让 `ptrace` 返回 `EPERM`，正常玩家也会被误杀）。打分制下，只有**多项同时可疑**
才动手——真实加固壳也普遍用这种"评分阈值"而不是单点定罪。
判定成立后 `wipe_mark()` 把 15 字节全写成 `'x'`，派生出的钥匙当然就不对了，
服务端既不返回数字（未命中真标记）、也不会给诱饵的 403。

`Gk.nativeStatus()` 是**只读自检**：只报告命中了哪些信号、当前评分与是否 TRIPPED，
不还原、不判胜、不吐标记，可以放心拿来做 bypass 效果的对照。

---

#### 路线一：静态逆（还原点解链 + 看懂哨兵）

`EXTRACTED[15]` 与还原点和 KL18 同构，参数不同：

```c
static const unsigned char EXTRACTED[15] = {
    0x23,0x53,0xbc,0xce,0x18,0x40,0x45,0x9f,
    0xf0,0x12,0x53,0x81,0xb1,0xf8,0x2c
};
/* ks(i) = (0x3F + 53*i) & 0xFF，首字节前导 0x5A */
static void restore_all(void) {
    unsigned char prev = 0x5A;
    for (int i = 0; i < 15; i++) {
        unsigned char v = EXTRACTED[i] ^ ks(i) ^ prev;
        g_mark[i] = (char)v; prev = v;      /* 链式：后一字节依赖前一字节 */
    }
    g_mark_len = 15; g_mark[15] = 0;
}
```

```
ks(i)         = (0x3F + 53*i) & 0xFF
EXTRACTED[i]  = mark[i] ^ ks(i) ^ (i == 0 ? 0x5A : mark[i-1])
CRC32(EXTRACTED) = 0x53006fcd        /* 自校验基线，改表必炸 */
```

注意：静态把还原点逆出来**不等于拿到标记**——真机上跑 `nativeMarker()` 还要过哨兵。
静态方案的正确用法是：离线用上面的公式算出标记，然后自己签名发包，完全绕开运行时。

---

#### 路线二：动态——先 bypass，再触发还原

**Step 1：让哨兵失明（至少压到 <2 分）**

```javascript
// ① ptrace：强制返回 0（成功）
Interceptor.attach(Module.findExportByName('libc.so', 'ptrace'), {
    onLeave: function (retval) { retval.replace(0); }
});

// ② TracerPid：把读到 status 的内容里的 TracerPid 改成 0
Interceptor.attach(Module.findExportByName('libc.so', 'open'), {
    onLeave: function (retval) {
        // 配合 read hook 把 "TracerPid:\t1234" 替换成 "TracerPid:\t0"
    }
});

// ③ 27042 端口：让 connect 失败
Interceptor.attach(Module.findExportByName('libc.so', 'connect'), {
    onEnter: function (args) {
        var port = (args[1].add(2).readU8() << 8) | args[1].add(3).readU8();
        this.isFrida = (port === 27042);
    },
    onLeave: function (retval) { if (this.isFrida) retval.replace(-1); }
});
```

嫌麻烦也可以直接 patch：把 `GUARD_THRESHOLD` 抬高，或把 `bs_guard_tripped()`
的返回改成恒 0——静态 patch 掉比较点即可。

**Step 2：触发还原并取值**

```javascript
Java.perform(function () {
    var Gk = Java.use('com.fatdog.reverse.Gk');
    console.log('status:', Gk.nativeStatus());   // 先看评分，确认已压到 clean
    console.log('marker:', Gk.nativeMarker());   // 触发还原点 → Fatdog_rekindle
    console.log('decoy :', Gk.nativeDecoy());    // Fatdog_rekindles
});
```

**Step 3（可选）：内存 dump**
扫 `/proc/<pid>/maps` 找 `libbison.so` 的 `rw-p` 段读 `/proc/<pid>/mem` 抠 `.bss`：
**哨兵未 bypass 时**这里要么是 nop、要么是 `'x'` 一片——正好用来验证 bypass 是否生效。

---

#### 完整 Python 复刻（离线解链 → 派生钥匙 → 取数 → 求和）

```python
import hashlib, hmac, random, time, json, urllib.parse, urllib.request

# ---- 1. 离线走一遍还原点：逐字节解链（顺序依赖）----
EXTRACTED = bytes([0x23,0x53,0xbc,0xce,0x18,0x40,0x45,0x9f,
                   0xf0,0x12,0x53,0x81,0xb1,0xf8,0x2c])

def ks(i):
    return (0x3F + 53 * i) & 0xFF

mark = bytearray()
prev = 0x5A
for i, e in enumerate(EXTRACTED):
    v = e ^ ks(i) ^ prev
    mark.append(v)
    prev = v
print("mark =", bytes(mark).decode())           # Fatdog_rekindle

# 顺手核对 SO 自校验基线
import zlib
print("crc32 =", hex(zlib.crc32(EXTRACTED) & 0xFFFFFFFF))   # 0x53006fcd

# ---- 2. 派生 HMAC 钥匙并对请求签名（完全绕开运行时哨兵）----
KEY = hashlib.sha256(bytes(mark) + b"kl19").digest()[:32]

def sign(page, ts):
    return hmac.new(KEY, ("page=%d&ts=%d" % (page, ts)).encode(),
                    hashlib.sha256).hexdigest()

# ---- 3. 100 页取数求和 ----
def fetch(page):
    ts = int(time.time())
    q = urllib.parse.urlencode({"page": page, "ts": ts, "sign": sign(page, ts)})
    with urllib.request.urlopen("https://127.0.0.1:8443/api/kl19?" + q, timeout=5) as r:
        return json.loads(r.read().decode())["nums"]

total = sum(sum(fetch(p)) for p in range(1, 101))
print("sum =", total)                            # 50475

# ---- 3'. 离线等价（服务端 SEED 固定）----
rng = random.Random(20260119)
print("offline sum =", sum(rng.randint(1, 100) for _ in range(1000)))   # 50475

# ---- 4. 提交：sha256(str(sum)) ----
print("SUM_HASH =", hashlib.sha256(str(total).encode()).hexdigest())
```

**服务端取数结果**

- `SEED_KL19 = 20260119`，100 页 × 10 个 → 1000 个数
- 加和 **50475**
- `SUM_HASH = 1e1eae8b16ff41d6ca9a0713b16abc7dcdb6115080e162074dce1c4f6e241975`

---

#### 坑位提醒

1. **哨兵没 bypass 就 dump，拿到的是 `'x'` 或 nop**——不是你的 dump 姿势不对，
   是它真的把东西抹了。先 `nativeStatus()` 确认 `clean` 再动手。
2. **阈值是 2，不是 1**——只绕过一处（比如只 hook 端口）通常不够：
   真机上 Frida 一附，TracerPid、maps、端口至少同时中 2~3 项。反过来，
   单个信号误报不会误杀正常玩家，这是刻意的防误报设计。
3. **自校验查的是"那张表"**——`CRC32(EXTRACTED) != 0x53006fcd` 记 1 分。
   想改表注入自己的标记，会同时吃这一分；而即便绕过，服务端也只认 `Fatdog_rekindle`。
4. **`nativeStatus()` 只读**——不还原、不判胜、不吐标记，可以反复调用对照 bypass 效果。
5. **解链仍是顺序依赖**——`mark[i]` 依赖 `mark[i-1]`，首字节前导 `0x5A`（KL18 是 `0x3C`，别混）。
6. **签名对象是 `page=N&ts=T` 原文**，`ts` 600 秒窗口；本关同样没有 AES 加密请求体。

**flag**：`FLAG_18_KL19{debug_beaten}`

---

### KL20：破壁飞升（三代壳 · 腾讯乐固·不落地 + SO 加固 + anti-frida） `abyssActivity` + `Zq` + `libdelta.so`

**考点**：太玄之初的收官卷，把"不落地"推到极致——仿腾讯乐固：DEX 在内存里解密、绝不写回磁盘，
SO 自身也加了加固。机制上仍沿用 KL17-19 的「抽空 → 还原点填回 → 派生钥匙签名取数」，
但还原点外面裹的是**乐固守卫（anti-frida）**：盘问 memory map 的熟面孔、本该安静的端口、tmp 下那条管道，
连自己那张表动没动过都要验。正解顺序和 KL19 一样：**先让守卫失明 → 再触发还原 → 拿标记 → 派生钥匙签名取数**。

- 真标记：`Fatdog_unsheathe`（16 字节）
- 明文诱饵：`Fatdog_unsheathes`（多一个 s）
- so：`libdelta.so`（C++17）；JNI 桥：`Zq`（`loadLibrary("delta")`）；活动页：`abyssActivity`
- 请求：`GET /api/kl20?page=N&ts=T&sign=<hex>`

---

#### 「不落地」是怎么落地的

磁盘 ELF 里只有两样东西：① 诱饵 `Fatdog_unsheathes`（明文，strings 可见）；
② 真标记的**密文分片** `EXTRACTED[16]`（静态段，非明文）。真标记运行时才由一块
**mmap 匿名内存**持有，走还原点逐字节拼回——不在磁盘落明文，这也是乐固"不落地"的题眼。

```c
static const unsigned char EXTRACTED[16] = {
    0x2F,0x34,0xDF,0x7F,0xF9,0x90,0xFC,0xD1,
    0xC2,0x13,0xBC,0x35,0x45,0x07,0x34,0xD1
};
/* ks(i) = (0x55 + 37*i) & 0xFF，首字节前导 0x3C；链式还原 prev 跟随上一字节密文 */
static void restore_all(void) {
    unsigned char prev = 0x3C;
    for (int i = 0; i < 16; i++) {
        unsigned char v = EXTRACTED[i] ^ dl_ks(i) ^ prev;
        g_mark[i] = (char)v; prev = EXTRACTED[i];   /* 与生成端同链 */
    }
    g_mark_len = 16; g_mark[16] = 0;
}
```
```
ks(i)          = (0x55 + 37*i) & 0xFF
EXTRACTED[i]   = mark[i] ^ ks(i) ^ prev_gen      /* prev_gen 即上一字节密文 */
CRC32(EXTRACTED) = 0xDCE53BFA      /* 自校验基线，改表必炸 */
```

---

#### 乐固守卫：anti-frida 四信号评分（含防误报设计）

```c
static int dl_guard_hits(void) {
    int h = 0;
    h += dl_hit_maps();          /* ① /proc/self/maps 含 frida / gadget / gum */
    h += dl_hit_frida_port();    /* ② connect 127.0.0.1:27042 成功            */
    h += dl_hit_pipe();          /* ③ /data/local/tmp/frida-* 命名管道        */
    h += (dl_crc32(EXTRACTED,16) != 0xDCE53BFA); /* ④ SO 自校验：表被动过 */
    return h;
}
#define GUARD_THRESHOLD 2        /* 命中 ≥2 项才判定注入 */
```

和 KL19 一样用**评分阈值 ≥2** 防误报：单项信号（比如某些 ROM 让 ptrace 直接 EPERM）不会误杀正常玩家；
多项同时可疑才动手。`wipe_mark()` 把 16 字节全写成 `'x'`，派生出的钥匙不对，服务端既不返回数字、也不给 403。
`Zq.nativeStatus()` 是只读自检：只报告命中信号与是否 TRIPPED，不还原、不判胜、不吐标记。

---

#### 路线一：静态逆（还原点解链）

链式的逆非常简单——从 `0x3C` 起，逐字节 `mark[i] = EXTRACTED[i] ^ ks(i) ^ EXTRACTED[i-1]`（首字节前导 `0x3C`）。
离线算出 `Fatdog_unsheathe` 后，自己派生钥匙签名发包，完全绕开运行时：

```python
import hashlib, hmac
EXTRACTED = [0x2F,0x34,0xDF,0x7F,0xF9,0x90,0xFC,0xD1,
             0xC2,0x13,0xBC,0x35,0x45,0x07,0x34,0xD1]
def ks(i): return (0x55+37*i)&0xFF
prev=0x3C; mark=bytearray()
for i in range(16):
    v=EXTRACTED[i]^ks(i)^prev; mark.append(v); prev=EXTRACTED[i]
print(bytes(mark))   # b'Fatdog_unsheathe'
```

---

#### 路线二：动态——先 bypass anti-frida，再触发还原

**Step 1：让守卫失明（压到 <2 分）**

```javascript
// ② TracerPid：把读到的 status 里的 TracerPid 改成 0
// ③ 27042 端口：让 connect 失败（返回 -1），frida-server 不在本就 0 分
// ① maps：hook open/read，把含 "frida"/"gadget"/"gum" 的行抹掉
// ④ CRC：别改 EXTRACTED 段，否则自校验直接 +1 分
Interceptor.attach(Module.findExportByName('libc.so','connect'), {
    onEnter(args){ /* 若目标 127.0.0.1:27042 则改写 sockaddr 指向不可达端口 */ }
});
```
压到 <2 分后，`nativeMarker()` / `nativeSign()` 走的就是真标记路径。

**Step 2：还原点 + 取数**

```javascript
// 直接调 nativeSign 拿签名，交给 /api/kl20
const sign = Java.use('com.fatdog.reverse.Zq').nativeSign(1, Date.now()/1000|0);
```

---

#### 路线三：乐固脱壳视角（不落地 DEX 还原）

本关取数走网络，DEX 不落地的"脱壳"更多是概念题眼；若把它当作真实乐固 DEX 来看：
**bypass anti-frida（hook open/read/connect 中和 maps 与 27042）→ frida-dexdump(`OpenMemory`) 抓内存里解密后的 DEX → 修 DEX 头**
（早期乐加固只加密 DEX 头 0x70 字节，补回即可）。本关真标记就在内存还原点里，dump 这段调用即得。

---

#### 网络求和（与 KL17-19 同源）

- `SEED_KL20 = 20260120`，100 页 × 10 个 → 1000 个数，总和 `sum = 51263`
- `SUM_HASH = sha256(str(51263)) = eb35acfd346379e2c981fb485c9af7e226bc145ba503b77623b2edc6420f622a`
- 钥匙 `key = sha256( mark + b"kl20" )[:32]`；签名 `sign = HMAC-SHA256(key, "page=N&ts=T")`
- 服务端真标记 `Fatdog_unsheathe` 验签放数；诱饵 `Fatdog_unsheathes` 命中即 403

```python
import random, hashlib, hmac, time
SEED=20260120
nums=[random.Random(SEED).randint(1,100) for _ in range(1000)]
s=sum(nums); assert hashlib.sha256(str(s).encode()).hexdigest()=="eb35acfd346379e2c981fb485c9af7e226bc145ba503b77623b2edc6420f622a"
key=hashlib.sha256(b"Fatdog_unsheathe"+b"kl20").digest()[:32]
ts=int(time.time())
sign=hmac.new(key,f"page=1&ts={ts}".encode(),hashlib.sha256).hexdigest()
# GET https://127.0.0.1:8443/api/kl20?page=1&ts={ts}&sign={sign}  → 10 个数；100 页求和得 51263
```

---

#### 坑位提醒

1. **链式的 prev 是密文不是还原值**——还原 `prev = EXTRACTED[i]`（上一字节密文），与生成端同链；若误写成 `prev = v`（还原值）会得到乱码。
2. **守卫是 ≥2 分定罪**——只 bypass 一项（如只 hook ptrace）仍可能 ≥2 分；maps/27042/管道至少压掉两路。
3. **诱饵标记** `Fatdog_unsheathes`（多 s）是假的，真标记 `Fatdog_unsheathe`。
4. **nativeStatus()** 只读自检，可放心对照守卫状态。

**flag**：`FLAG_18_KL20{legu_unboxed}`` |

#### 三层保护结构

| 层 | 技术 | 对应关卡 |
|---|---|---|
| 外层 | XOR + Base64 加密 | —（KL16/KL17 均已改为标准算法取数，不再走 XOR+Base64） |
| 中层 | OLLVM 状态机混淆 | —（KL18 已改为方法抽取取数，不再用 OLLVM） |
| 内层 | VMP 字节码执行 | —（KL19 已改为指令抽取+反调试取数，不再用 VMP） |
| 额外 | 反调试 + CRC 自校验 | — |

#### Hk 导出函数

| 函数 | 返回 | 说明 |
|---|---|---|
| `nativeAntiDebug()` | `int` | 反调试检查（ptrace + TracerPid） |
| `nativeDecrypt()` | `String` | 外层解密结果（hex） |
| `nativeSeed()` | `int` | 提取的种子值 |
| `nativeAnswer()` | `String` | 最终答案（SHA-256(seed)） |
| `nativeOllvm(int)` | `int` | 中层 OLLVM 变换 |
| `nativeVmExecute()` | `int` | 内层 VMP 执行结果 |
| `nativeStatus()` | `String` | 各层状态信息 |

#### 破解路线

1. **反调试绕过**：`nativeAntiDebug()` 检查 ptrace + TracerPid，绕过后才能正常调用其他函数。
2. **外层脱壳**：`nativeDecrypt()` → XOR 轮转解密 + Base64 解码 → 得到 hex 数据。
3. **中层分析**：`nativeOllvm(seed)` → OLLVM 状态机（8 个 case，含虚假路径）。
4. **内层逆向**：`nativeVmExecute()` → VMP 字节码（8 条指令，32 字节加密字节码）。
5. **答案计算**：从解密数据提取 seed → SHA-256(seed) → 32 位 hex。

#### 与前几关的关系

| 前关 | 复用点 |
|---|---|
| KL16 | 两阶段动态加载标记 + 标准 AES-128-ECB（一代壳取数） |
| KL17 | 类抽取四段回填标记 + 标准 HMAC-SHA256（二代壳取数） |
| KL18 | 方法抽取：还原点逐条填回 + 标准 HMAC-SHA256 |
| KL19 | 指令抽取还原点 + 反调试哨兵（五信号评分，阈值 2） |

#### 关键数据

| 内容 | 说明 |
|---|---|
| XOR_KEY | `5A 3C 7E 1D 92 64 A8 F0`（8 字节轮转） |
| ENC_DATA | 24 字节加密 Base64 数据 |
| OLLVM_ROL | 循环左移（13/7 位） |
| VM_BC_ENC | 32 字节加密字节码（XOR 0x5C） |
| MARKER | `Fatdog_break`（UTF-16LE，12 码元） |
| DECOY | `Fatdog_breaker`（UTF-16LE，14 码元） |

#### 坑位提醒

1. **三层叠加** → 必须逐层突破：反调试 → 外层 → 中层 → 内层，任何一层失败都拿不到答案。
2. **简化版 OLLVM/VMP** → 比真实加固壳的实现简单，但思路一致（注：KL18 已改为方法抽取取数，不再承担 OLLVM 教学）。
3. **诱饵标记** → `Fatdog_breaker`（多 er）是假的，真标记 `Fatdog_break`。
4. **nativeStatus()** → 调试利器，显示各层状态和反调试结果。

**flag**：`FLAG_18_KL20{all_shells_broken}`


> 太玄之初除了"三代壳"卷（KL16-20），还追加了独立编号的 C++ 壳教学卷 KKL1-5（玄冥渊 / 万剑冢 / 断魂谷 / 锁妖塔 / 诛仙台），全部由 `app/jni/kkl*.cpp` 实现。目前开放 KKL1-KKL4，KKL5 在 MainActivity 里仍是"尚未开启"占位。与 KL16-20 的壳课不同，KKL 卷强调**用 C++ 造现代壳零件**：虚表派发、抽取回填、动态注册、真 DEX 内存加载。

### KKL1：玄冥渊（太玄之初 · C++ vtable 派发 + 抽取回填）

**考点**：模拟二代壳"抽取回填"——真实密文被拆成 8 组 4 字节，按抽取表乱序散在 `POOL` 里（前 8 字节是永不参与的噪声）；运行时用表"回填"成 32 字节密文再解密。难点在于**抽取表不写死在主流程**：三个 C++ 派生类各通过虚函数 `table()` 交表，只有 `RealCipher` 是真身，另两个是 identity / reverse 假表——IDA 里认 vtable 结构、逐个派生类对表，就是本关的正解。

**静态复刻（Python）**：

```python
import hashlib
POOL = bytes([0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
              0xC5,0xD9,0x6D,0xF7,0x88,0x63,0x3A,0xC5,0x88,0x63,0x3A,0xC5,
              0x63,0x09,0x92,0x6D,0x4B,0xF8,0x2B,0xF1,0x4D,0x9E,0x2B,0xF1,
              0x24,0xF7,0xA2,0xD7,0xCE,0xA5,0x3C,0xE2])
TABLE = [6, 3, 0, 7, 4, 1, 5, 2]          # RealCipher::T（另两个类是假表）
KX = bytes([0x4D,0x9E,0x2B,0xF1,0x88,0x63,0x3A,0xC5])

enc = bytearray()
for r in range(8):                          # 抽取回填（跳过 8 字节噪声）
    enc += POOL[8 + TABLE[r]*4 : 8 + TABLE[r]*4 + 4]
plain = bytearray()
for i in range(32):                         # XOR → 循环左移 3 位
    v = enc[i] ^ KX[i % 8]
    plain.append(((v << 3) | (v >> 5)) & 0xFF)
print(plain[:16])                           # b'KKL1_SEED:20260903' + 0x00 填充
seed = int(bytes(plain[10:18]))             # 20260903
ans = hashlib.sha256(seed.to_bytes(4, 'big')).hexdigest()
print(ans)
```

**答案**：`22f86ebbe7c758e10ca3ae0f048f5f4dede0d6aaf9022d5419a7e7874245778d`；flag `FLAG_18_KKL1{abyss_of_mystery}`。真标记 `Fatdog_hallow`（UTF-16 藏 `.data`）/ 诱饵 `Fatdog_hollow`（hallow→hollow）。

**动态路线**：Frida hook 桥 `Kkl1Native` 的 `nativeDecrypt/nativeSeed/nativeAnswer` 直接对拍；想练 vtable 就 IDA 里从 `make_cipher()` 的 switch 出发，逐个类看 `table()` 返回的 8 字节表。**坑**：诱饵类解出的明文是乱码，`choose_selector` 恒走 0（真身），别把假表的解当结论。

### KKL2：万剑冢（太玄之初 · 真 DEX 内存加载 + 动态注册 + 服务端取数）

**考点**：业务 DEX（`com.fatdog.reverse.kkl2.GateKeeper2`）构建期被加密成 `assets/kkl2/echoes_of_blades.bin` 埋进 APK；旁边那个 `assets/kkl2/classes_decoy.dex` 是假壳（真壳形状假内容）。`libkkl2.so`（桥 `Kkl2Native`）导出表**没有 Java_ 符号**——两个 native 是 `JNI_OnLoad` 里动态注册的：

- `nativeUnseal(enc)`：流式解密还原明文 dex（App 用 `InMemoryDexClassLoader` 内存加载，不落盘）；
- `nativeDeriveKey()`：返回 32 字节 HMAC 密钥。

解密链故意走 STL（容器逆向 / lambda 捕获 / `std::swap` 是教学点）：密钥 `dk = SHA-256("Fatdog_tense" + "|kkl2_swordfield")`（真标记以 UTF-16 码元藏 `.data`，`strings -el` 才见；明文 `Fatdog_timid` 是诱饵，用它派生密钥验签全 403）→ 偶数下标与镜像位交换 → 加性 keystream（`acc = dk[0]^0x5A`，逐字节 `acc += dk[i%32]`）→ 流式 XOR。

**取数链路（Python 复刻）**：解出 dex 后 jadx 看 `GateKeeper2.sign(key, page, ts)` = `HmacSHA256(key, "page=N&ts=T")`；逐页 GET `/api/kkl2` 带 `page/ts/sign`：

```python
import hashlib, hmac, time, requests
key = hashlib.sha256(b'Fatdog_tense|kkl2_swordfield').digest()
total = 0
for page in range(1, 101):
    ts = int(time.time())
    sign = hmac.new(key, f'page={page}&ts={ts}'.encode(), hashlib.sha256).hexdigest()
    r = requests.get('https://127.0.0.1:8443/api/kkl2',
                     params={'page': page, 'ts': ts, 'sign': sign},
                     verify='certs/ca.crt', timeout=5).json()
    total += sum(r['nums'])                 # 每页 10 个数
print(total)                                # 49755
print(hashlib.sha256(str(total).encode()).hexdigest())
```

**答案**：100 页加和 = `49755`，提交 `sha256("49755")` = `00ed53989532cff023fc7776f13e584d75149e80f528b1f8d079de7d9bdabb13`（64 hex，大小写不敏感）；flag `FLAG_18_KKL2{tomb_of_myriad_blades}`。

**Frida 最短路线**：hook `Kkl2Native.nativeDeriveKey`（拿 key）+ hook `nativeUnseal` 出口把 dex 写回文件 → jadx 看 `sign` 逻辑照抄。**坑**：dump 时机要在 `InMemoryDexClassLoader` 构造点或 native 出口，晚了 dex 只在内存；服务端按 `seed 20260909` 生成 1000 个数（`random.Random(20260909).randint(1,100)`），本地可离线复算对拍。


### KKL3：断魂谷（太玄之初 · 四路哨兵 + 静默投毒 + 服务端取数）

**考点**：检测按钮本身永远不通关。`libkkl3.so` 的四路哨兵只在 `Kkl3Native.nativeSign(page, ts)` 每次取数签名前跑：`TracerPid`/ptrace 痕迹、maps 里的 frida/gadget/librun/gum-js/linjector、27042-27044 端口探测、`/proc/self/task/*/comm` 的 frida 线程名。任何一路命中就把 HMAC 密钥第 8 字节的 `0x40` 位永久翻转，此后签出的每一页都会被 `/api/kkl3` 静默 403——没有弹窗、没有错误码以外的提示。`nativeStatus()` 只做只读自检，点了也不会改变密钥，别把它当成过关入口。

**静态路线**：strings 里能看到明文诱饵 `Fatdog_quiet`，但真标记是 UTF-16 藏匿的 `Fatdog_quell`（用 `strings -el lib/arm64-v8a/libkkl3.so` 或 IDA 的 UTF-16 视图即可看到 12 个码元）。密钥派生就是 `SHA-256("Fatdog_quell" + "|kkl3_valley")`，之后逐页取数求和：

```python
import hashlib, hmac, time, requests
key = hashlib.sha256(b'Fatdog_quell|kkl3_valley').digest()
total = 0
for page in range(1, 101):
    ts = int(time.time())
    sign = hmac.new(key, f'page={page}&ts={ts}'.encode(), hashlib.sha256).hexdigest()
    r = requests.get('https://127.0.0.1:8443/api/kkl3',
                     params={'page': page, 'ts': ts, 'sign': sign},
                     verify='certs/ca.crt', timeout=5).json()
    total += sum(r['nums'])
print(total)                                # 52219
print(hashlib.sha256(str(total).encode()).hexdigest())
```

**答案**：100 页加和 = `52219`，提交 `sha256("52219")` = `5b675c4a63fbc84ebc0478f244d3c63093d57d6a1eca7df8618dbf1485c92fd7`（64 hex，大小写不敏感）；flag `FLAG_18_KKL3{valley_of_the_sentinel}`。

**patch/hook 路线**：目标是让四路哨兵在签名前全部判安全，而不是改 `nativeStatus()`。常见做法：nop 掉 `run_sentinels(true)` 的调用点或让四个 `detect_*` 恒返 0；注意进程一旦已被投毒，密钥在内存里已经翻位，patch 后要重启进程。服务端 seed 是 `20260916`（`random.Random(20260916).randint(1,100)` 生成 1000 个数），本地可离线复算对拍。

### KKL4：锁妖塔（太玄之初 · 代码段 CRC + 三点记账 + 服务端取数）

**考点**：`libkkl4.so` 先读 `/proc/self/maps` 定位自己的可执行段，再对 `nativeOpen` / `nativeSign` / `nativeCommit` / `kkl4_crc_check` 四个窗口做 CRC-32 自校验（基线由 `tools/gen_kkl4_crc_baseline.py` 在构建期烘焙，放在独立 `kkl4_baseline.c`，不做运行时自证）。真机关不在 `nativeStatus()`：每页请求前 `nativeSign` 都要过 open→sign→Java 回调 commit 的三点记账，任一函数被静态 patch 或 inline hook，代码窗口 CRC 立即失配，HMAC 密钥被永久投毒，`/api/kkl4` 静默 403。

**静态路线**：strings 能看到明文诱饵 `Fatdog_grim`，真标记是 UTF-16 藏匿的 `Fatdog_grit`（`strings -el lib/arm64-v8a/libkkl4.so` 可看到 11 个码元）。密钥派生与 KKL3 同构，`key = SHA-256("Fatdog_grit" + "|kkl4_tower")`，之后不依赖 so 直接逐页取数求和：

```python
import hashlib, hmac, time, requests
key = hashlib.sha256(b'Fatdog_grit|kkl4_tower').digest()
total = 0
for page in range(1, 101):
    ts = int(time.time())
    sign = hmac.new(key, f'page={page}&ts={ts}'.encode(), hashlib.sha256).hexdigest()
    r = requests.get('https://127.0.0.1:8443/api/kkl4',
                     params={'page': page, 'ts': ts, 'sign': sign},
                     verify='certs/ca.crt', timeout=5).json()
    total += sum(r['nums'])
print(total)                                # 51434
print(hashlib.sha256(str(total).encode()).hexdigest())
```

**答案**：100 页加和 = `51434`，提交 `sha256("51434")` = `6e769234a6eaaeb3118e6444cb116fb4f72935cd7f947400c1eee0bee368c62b`（64 hex，大小写不敏感）；flag `FLAG_18_KKL4{tower_of_the_sealed}`。

**patch/hook 路线**：不要只改 `nativeStatus()`。四点记账要求 open 先置位、sign 与 commit 交替闭合；inline hook `kkl4_crc_check` 或任一 JNI 入口都会改写前几条指令，CRC 窗口自己会先失配。想靠 patch 走通，必须完整重建 CRC 与记账链路（进程已被投毒时先重启）；最省事仍是静态还原 UTF-16 真标记派生密钥直接复刻请求。服务端 seed 是 `20260923`（`random.Random(20260923).randint(1,100)` 生成 1000 个数）。

### KKL5：诛仙台（太玄之初 · VMP + onCreate 抽取 + AES-128-CBC）

#### 一、这一关在考什么

KKL5 对齐 360 加固对 `Activity.onCreate` 的处理方式：**原始 `onCreate` 的关键逻辑不在 dex 里，而是被抽成 native，交给壳 SO 里的解释器逐条解密执行**（参考 360 加固脱壳笔记：`StubApp.interface11` 把 `onCreate` 注册到壳 SO 的 native 方法，解释器按 case 还原 Dalvik 指令）。本关把这个手法做成可控的教学版：

- `kkl5Activity.onCreate()` 只做三件事：构建视图、调用 `Kkl5Native.nativeOnCreate(this)`、放行翻页取数；
- 真正的门禁在 `libkkl5.so` 的 `kkl5_on_create_gate()` 里，由自定义寄存器 VM 解释执行字节码得出；
- 门禁通过后才派生取数用的 AES/MAC 子钥；取数协议是 AES-128-CBC + HMAC-SHA256 复合签名；
- 业务 DEX（`com.fatdog.reverse.kkl5.GateKeeper5`）用同一个 AES 密钥加密埋在 `assets/kkl5/ascension_altar.bin`，运行时 `nativeUnseal()` 解密后内存加载。

一句话：`onCreate` 是入口，VM 是机关，AES-CBC 是取数协议，服务端只认由真标记派生出的签名。

#### 二、VM 架构与字节码格式

`app/jni/kkl5.cpp` 里的解释器是寄存器式 VM：

- 16 个 32 位虚拟寄存器 `V0`-`V15`；
- 指令长度固定 32 位，小端存储；
- 指令编码：`opcode << 24 | imm16`，即最高字节是操作码、低 16 位是立即数（KKL5 开发时曾把 opcode 放低字节、立即数放高 16 位，与解释器解码方向相反导致 VM 死循环，后统一为现在这个格式）；
- 指令集：`MOV / ADDI / XOR / XORI / AND / OR / SHL / SHR / ROL / ROR / CMP / JMP / JZ / JNZ / ADD / SUB / MUL / HALT`；
- 字节码不是明文：`bytecode[i] ^= kKkl5VmRollingKey[i % 32]`，滚动密钥是 `0x11..0x30` 共 32 字节，存在 `kkl5_vm_program.h`；
- `MOV` 是双字指令：低 16 位和高 16 位各发一条，解释器第一次保留低半区、第二次把立即数移进高半区，这样就能装下 32 位常量。

字节码程序本身做的是**逐字节密钥派生**：对 `i = 0..15`（AES 主钥）或 `0..31`（MAC 子钥），按标记和盐计算

```
k = ((marker[i % len(marker)] * 0x1F + salt[i % len(salt)] * 0x2B + i * 0x11)
     ^ (marker[i % len(marker)] << 1)) 旋转左移 8 位 3 位  ^ salt[i % len(salt)]
```

再按 `i % 4` 塞进第 `1 + i/4` 号寄存器，最后从寄存器读回 16/32 字节。真标记 `Fatdog_ascend` 是 VM 里的立即数；诱饵 `Fatdog_ascent` 是另一份字节码，服务端只认真标记派生的签名。

#### 三、密钥与协议参数

| 参数          | 值                                                           |
| ------------- | ------------------------------------------------------------ |
| 真标记        | `Fatdog_ascend`（VM 立即数）/ 诱饵 `Fatdog_ascent`           |
| AES 主钥      | `6a3315b12737d2b16d2ed50ddf8d4852`（16 字节，VM 派生）       |
| MAC 子钥      | `SHA256(aes_key + "\|kkl5_ascension")` = `af529d9976ff1c367d3b265757362d0efce4d7d43120d7245fce4fae28d72714` |
| 响应 AES 密钥 | `SHA256("Fatdog_ascend\|kkl5_response")[:16]`                |
| 请求 IV       | `SHA256("page=N\|ts=T\|" + mac_key)[:16]`                    |
| 请求密文      | `AES-128-CBC(aes_key, PKCS7("page=N&ts=T"))`，`enc = hex(IV + 密文)` |
| 请求签名      | `HMAC-SHA256(mac_key, enc)`                                  |
| 响应 IV       | `SHA256("N\|T\|" + rsp_key.hex())[:16]`                      |
| 响应签名      | `HMAC-SHA256(mac_key, "N\|T\|ivHex\|dHex")`                  |
| 页数 / 种子   | 100 页 × 10 个数字；seed `20260930`                          |
| 加和 / 提交   | 53011 / `sha256("53011")` = `5c1f9a36a76360acdb86b6859da42f3ea7abe57ba5f5d836066039885f619924` |
| flag          | `FLAG_18_KKL5{ascension_of_the_immortals}`                   |

服务端 `/api/kkl5` 先校验 page/ts，再用 MAC 子钥验 `sign`，然后解 AES-CBC、比对明文是否等于 `page=N&ts=T`，最后返回 `{"iv":..., "d":..., "sign":...}`。任一环节不符返回 403。

#### 四、静态复刻路线（推荐）

**第 1 步：解出 VM 字节码。** 把 `kkl5_vm_program.h` 里的 `kKkl5VmProgramEnc` 与 `kKkl5VmRollingKey` 取出来，逐字节异或还原成 32 位指令流：

```python
enc = list(kKkl5VmProgramEnc)
key = bytes(range(0x11, 0x31))
words = []
for i in range(0, len(enc), 4):
    w = 0
    for j in range(4):
        w |= (enc[i + j] ^ key[(i + j) % 32]) << (j * 8)
    words.append(w)
```

**第 2 步：实现解释器。** 解码 `op = (w >> 24) & 0xFF`、`imm = w & 0xFFFF`，按上表实现 switch 即可。跑完 `kKkl5VmProgramEnc` 得到 AES 主钥，跑 `kKkl5VmMacEnc` 得到 MAC 子钥。实际产物里这两个值是：

```
aes_key = 6a3315b12737d2b16d2ed50ddf8d4852
mac_key = af529d9976ff1c367d3b265757362d0efce4d7d43120d7245fce4fae28d72714
```

**第 3 步：复刻请求协议并逐页取数。** 下面的脚本可直接跑通（先用 `python server.py` 起服务）：

```python
# solutions_kkl5.py —— KKL5 诛仙台完整复刻
import hashlib, hmac, json, ssl, time, urllib.request
from Crypto.Cipher import AES

BASE = "https://127.0.0.1:8443"
AES_KEY = bytes.fromhex("6a3315b12737d2b16d2ed50ddf8d4852")
MAC_KEY = hashlib.sha256(AES_KEY + b"|kkl5_ascension").digest()
RSP_KEY = hashlib.sha256(b"Fatdog_ascend|kkl5_response").digest()[:16]


def pkcs7_pad(data):
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def unpad(data):
    return data[:-data[-1]]


def fetch_page(page, ts):
    plain = f"page={page}&ts={ts}".encode()
    iv = hashlib.sha256(f"{page}|{ts}|".encode() + MAC_KEY).digest()[:16]
    ct = AES.new(AES_KEY, AES.MODE_CBC, iv).encrypt(pkcs7_pad(plain))
    enc = (iv + ct).hex()
    sign = hmac.new(MAC_KEY, enc.encode(), hashlib.sha256).hexdigest()
    body = f"page={page}&ts={ts}&enc={enc}&sign={sign}".encode()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(BASE + "/api/kkl5", data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    rsp = json.loads(urllib.request.urlopen(req, context=ctx, timeout=10).read())
    # 验响应签名：HMAC(mac_key, "page|ts|ivHex|dHex")
    msg = f"{page}|{ts}|{rsp['iv']}|{rsp['d']}".encode()
    expect = hmac.new(MAC_KEY, msg, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(expect, rsp["sign"]), "响应签名不匹配"
    pt = AES.new(RSP_KEY, AES.MODE_CBC, bytes.fromhex(rsp["iv"])).decrypt(bytes.fromhex(rsp["d"]))
    return json.loads(unpad(pt))["nums"]


ts = int(time.time())
total = 0
for page in range(1, 101):
    nums = fetch_page(page, ts)
    total += sum(nums)
    if page % 10 == 0:
        print(f"page {page:3d}: partial sum = {total}")

print("sum =", total)
print("submit =", hashlib.sha256(str(total).encode()).hexdigest())
```

跑完输出 `sum = 53011`，提交 `5c1f9a36a76360acdb86b6859da42f3ea7abe57ba5f5d836066039885f619924` 即通关。

**第 4 步：如果要走 so 反汇编。** 也可以用 jadx 看 `kkl5Activity.onCreate` → `Kkl5Native.nativeOnCreate` → `System.loadLibrary("kkl5")`，再用 IDA/Ghidra 打开 `libkkl5.so`，重点看 `kkl5_vm_run` 的 switch、`kkl5_on_create_gate` 的寄存器读取，以及 `nativeSign` 里 AES-CBC + HMAC 的调用顺序。VM 字节码在 `.rodata`，滚动密钥常量同样在附近。

#### 五、动态路线

- Frida hook `Kkl5Native.nativeSign(page, ts)`：直接拿 `enc|sign` 字符串，不用自己实现 AES/HMAC，然后照第 3 步拼请求即可；
- Frida hook `Kkl5Native.nativeUnseal(sealed)`：拿到解密后的业务 DEX，dump 出来可确认 `GateKeeper5` 内容；
- patch `kkl5_on_create_gate` 或 VM 字节码：门禁会直接失败，因为 `kkl5_on_create_gate` 会把派生出的主钥与 `kKkl5VmExpectAes` 比对，patch 后签名被投毒，服务端 403。

#### 六、常见坑

1. `enc` 是 `IV + 密文` 的 hex，不是纯密文；服务端解密时从 `enc[:16]` 取 IV；
2. 请求 IV 和响应 IV 的派生公式不同，响应 IV 是服务端算好通过 `iv` 字段下发的，不要自己重算；
3. MAC 子钥不是 `SHA256(marker)`，而是 `SHA256(aes_key + "|kkl5_ascension")`，即先有 VM 派生的 AES 主钥，再有 MAC 子钥；
4. VM 字节码解码时 opcode 在最高字节，`w = (w >> 24) & 0xFF`；写成 `w & 0xFF` 会得到完全错误的指令流；
5. 服务端 seed 固定为 `20260930`，同一页的 10 个数字固定，换时间戳不会改变数字本身。

## 天地秘境 · 扶桑树（KL21-28）


> 扶桑树八关统一主题：**Frida 反检测对抗**。每关 `libXXX.so` 导出同一组函数形态——`nativeXxx()`（各路子检测）、`nativeFridaDetect()`（综合判定，0=安全/1=检出）、`nativeAnswer()`（**最终答案，已与检测结果绑定**）、`nativeStatus()`（检测报告详情）；App 里点「运行检测」看结果、提交 `nativeAnswer()` 的返回值。
>
> ⚠️ **路线1（答案与检测绑定，2026-09 改造后生效）**：`nativeAnswer()` 内部先调用综合检测；**一旦检出 Frida，直接返回固定锁定串 `DETECTED_FRIDA_LOCKED_ANSWER`（提交必败）；只有"未检出"时才返回下方真答案（算法不变）**。因此这 8 关现在能真练到"绕过/对抗"——不 defeat 检测就拿不到 flag。
> - 想通关：挂 Frida 后必须先把 `nativeFridaDetect`（或各 `detect_*` 子路）打掉，让 App 在"未检出"窗口内算出真 hash 并提交；光用 Frida 读 `nativeAnswer` 拿到的是锁定串。
> - App 端：点「运行检测」若命中会弹"已被 Frida 检测"对话框；提交时若仍处于被检测状态会直接拦截提示。
> - `nativeStatus()` 报告的 `REAL_MARK`/`FAKE_MARK`（如 `Fatdog_breeze`/`Fatdog_gust`）**只是演示文本，纯干扰，不参与答案**——别被"两个标记一真一假"带偏。
>
> 两个通用认知：
> 1. **综合判定是"判定逻辑"的训练场**——OR / AND 的绕过策略不同：OR 全绕、AND 破一路即可（KL23/KL25 是 AND，漏任一路都不会误报）；
> 2. **答案算法**：KL21-23 是 `SHA-256(seed 的 4 字节大端)`，KL24-28 是 LCG 伪随机 hex。下面表格里的答案是**未检出时的真值**；下表只是结论，静态复刻见下方脚本。

| 关卡 | 名称 | 判定 | 检测点 | seed | 答案（32 hex） | flag |
|---|---|---|---|---|---|---|
| KL21 | 枯叶听风 | OR | 端口 27042-27044 + D-Bus 指纹 | 20280715 | `509b85ba58729bb4934d5467a7c01c508f82f09ea2f660d703591cc233bb172b` | `FLAG_18_KL21{leaf_hears_the_wind}` |
| KL22 | 落影寻痕 | OR | fd memfd + maps 关键词 | 20280716 | `7ece99ec50816dca8130a166dff30227d8ef546fbf97f5370a1ff5fc2caff2c6` | `FLAG_18_KL22{shadow_leaves_no_trace}` |
| KL23 | 照妖显形 | AND | maps 特征字节 + 运行时 DT_DEBUG + auxv 一致性 | 20280717 | `7553ec6d375135f8fb11dcf5a0a6f50060c6a68a05a9147f88f8771db5083bbb` | `FLAG_18_KL23{mirror_shows_true_face}` |
| KL24 | 冰鉴悬镜 | OR | TracerPid + State | 20280718 | `83abc5a60bf846a88404c66b0cf24701` | `FLAG_18_KL24{ice_mirror_catches_all}` |
| KL25 | 暮雾锁听 | AND | Frida maps/线程指纹 + auxv 一致性 | 20280719 | `c8c20ef9499a87f1c94e0fc64ab1886c` | `FLAG_18_KL25{mist_locks_the_ears}` |
| KL26 | 暮霭沉沉 | OR | 稳定 timing + 版本嗅探 | 20280720 | `8ac8cc07027b4d6d8bf9cd8003454e71` | `FLAG_18_KL26{dusk_hides_the_truth}` |
| KL27 | 轻纱覆影 | OR | 线程上下文 + 时序交叉 | 20280721 | `4cc08a01cc4402bc4da28b32cdcd0386` | `FLAG_18_KL27{veil_conceals_all}` |
| KL28 | 雪落无痕 | OR | signal handler + TracerPid | 20280722 | `8399c59f0bec469884fec6510ce347fc` | `FLAG_18_KL28{snow_leaves_no_trace}` |

通用复刻脚本（真值对拍用）：

```python
import hashlib
def sha_ans(seed):                      # KL21-23
    return hashlib.sha256(seed.to_bytes(4,'big')).hexdigest()

def lcg_ans(seed):                      # KL24-28：libice 之后统一 LCG 伪 hex
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
        out.append('0123456789abcdef'[(h >> ((i % 4) * 4)) & 0xF])
        h = (h * 1664525 + 1013904223) & MASK
    return ''.join(out)
```

绕过思路（OR 家族通用）：hook `nativeFridaDetect` 出口改 0 最省事，但那就学不到检测本身了。正经路线是逐路子函数 hook：端口关→hook `connect`/屏蔽 27042-44；文件指纹关→hook `open/read/readlinkat/fopen` 喂假内容；ELF/auxv 关→hook `lseek/read` 或拦截 `/proc/self/exe`、`/proc/self/auxv`。每关正文只列本关要点，上面是公共底子。

### KL21：枯叶听风（libfox.so · 端口 + D-Bus）

- **综合判定** `detect_frida_present = detect_port_scan() || detect_dbus_fingerprint()` —— **OR**。
- **子路①端口探测**：`connect(127.0.0.1, 27042/27043/27044)`，300ms 超时，连上即中；
- **子路②D-Bus 指纹**：解析 `/proc/net/tcp`，找远端端口命中 27042-44 且状态 ESTABLISHED（01）的连接——Frida 经 D-Bus 与进程通信；
- **绕过**：hook `nativeFridaDetect`→0 最省事；正经路线——端口关 hook `connect` 屏蔽三端口 + hook 文件读过滤 `/proc/net/tcp`；或改 frida-server 默认端口（`-l 127.0.0.1:6666`）让 App 裸跑即"未检出"，用来验证理解。
- **静态答案（未检出时）**：seed `20280715` → `sha256` → `509b85ba58729bb4934d5467a7c01c508f82f09ea2f660d703591cc233bb172b`。flag `FLAG_18_KL21{leaf_hears_the_wind}`。
- *注：`nativeStatus` 里的 `Fatdog_breeze`/`Fatdog_gust` 仅为报告展示，与答案无关。*

### KL22：落影寻痕（libowl.so · fd + maps）

- **综合判定** `detect_frida_present = detect_fd_scan() || detect_maps_scan()` —— **OR**。
- **子路①fd 扫描**：遍历 `/proc/self/fd` 逐个 `readlink`，找 `memfd:frida-agent`；
- **子路②maps 搜索**：流式读取完整 `/proc/self/maps`，搜 `frida` / `gadget` / `gum-js-loop` 等关键词，并保留跨块重叠区；
- **绕过**：hook `nativeFridaDetect`→0；hook `readlinkat` 返回假路径（如 `/dev/null`）；hook `opendir`/`getdents` 过滤 fd；或干脆给 agent 改名/藏到非 memfd 路径。
- **静态答案（未检出时）**：seed `20280716` → `sha256` → `7ece99ec50816dca8130a166dff30227d8ef546fbf97f5370a1ff5fc2caff2c6`。flag `FLAG_18_KL22{shadow_leaves_no_trace}`。
- *注：`Fatdog_shadow`/`Fatdog_shade` 仅为报告展示，与答案无关。*

### KL23：照妖显形（libsun.so · 三路 AND）

- **综合判定** `detect_frida_present = detect_maps_hex() && detect_dt_debug() && detect_auxv()` —— **AND**（三路同时成立才检出，漏任一路都安全）。
- **子路①maps hex**：在 `/proc/self/maps` 的 r-xp 段里搜 frida 特征字节模式；
- **子路②运行时 DT_DEBUG**：通过 `dl_iterate_phdr` 和 `AT_PHDR` 定位主程序动态段，读取链接器写入内存的 `DT_DEBUG`；磁盘值为 0，不能离线读取判定；
- **子路③auxv**：读 `/proc/self/auxv` 与磁盘 ELF 头交叉校验，作为 ABI 无关的一致性守卫；
- **绕过**：hook `nativeFridaDetect`→0；或破坏 maps 特征路、`dl_iterate_phdr` 路径、auxv/ELF 一致性中的任意一条（AND 破一路即安全）。
- **静态答案（未检出时）**：seed `20280717` → `sha256` → `7553ec6d375135f8fb11dcf5a0a6f50060c6a68a05a9147f88f8771db5083bbb`。flag `FLAG_18_KL23{mirror_shows_true_face}`。
- *注：`Fatdog_gleam`/`Fatdog_glint` 仅为报告展示，与答案无关。*

### KL24：冰鉴悬镜（libice.so · 进程状态）

- **综合判定** `detect_frida = detect_tracer_pid() || detect_state()` —— **OR**。
- **子路①TracerPid**：读 `/proc/self/status`，`TracerPid` 非 0 即中（frida-gadget 注入常留下 tracer）；
- **子路②State**：进程状态字为 `t`（traced stop）/ `T`（stopped）即中；
- **绕过**：hook `nativeFridaDetect`→0；hook `fopen`/`fgets` 拦截 status 文件（喂 `TracerPid: 0`、`State: S (sleeping)`）；spawn 模式下注意别让检测发生在 tracer 挂上时。
- **静态答案（未检出时）**：seed `20280718` → LCG → `83abc5a60bf846a88404c66b0cf24701`。flag `FLAG_18_KL24{ice_mirror_catches_all}`。
- *注：`Fatdog_siren`/`Fatdog_sren` 仅为报告展示，与答案无关。*

### KL25：暮雾锁听（libmist.so · 三路 AND）

- **综合判定** `detect_frida = detect_maps_frida() && detect_frida_threads() && detect_auxv_hook()` —— **AND**。
- **子路①maps frida 特征**：搜 `/proc/self/maps` 中 frida/gadget 关键词；
- **子路②线程指纹**：枚举线程名，匹配 **frida 专属名**（`gum-js-loop`/`pool-frida`/`frida`/`linjector`）——已剔除 `gmain`/`gdbus` 等 GLib 误报源；
- **子路③auxv/ELF 一致性**：`AT_PHDR`/`AT_PHENT`/`AT_PHNUM` 与磁盘头对齐；
- **绕过**：hook `nativeFridaDetect`→0；或处理 maps 特征、线程名、auxv 校验中的任意一路（AND 破一路即安全）。
- **静态答案（未检出时）**：seed `20280719` → LCG → `c8c20ef9499a87f1c94e0fc64ab1886c`。flag `FLAG_18_KL25{mist_locks_the_ears}`。
- *注：`Fatdog_gloom`/`Fatdog_glom` 仅为报告展示，与答案无关。*

### KL26：暮霭沉沉（libdusk.so · 版本嗅探 + 计时印证）

- **综合判定** `detect_frida = detect_frida_version() || (timing && maps_frida)` —— **OR**。
- **子路①版本嗅探**：dlsym/maps 里找 frida 版本串，命中即中（主判据）；
- **子路②timing 侧信道**：clock 测耗时，9 轮采样取中位数 + 7 轮超阈值去抖；**已改为"计时异常必须与 maps 中 frida/gadget 特征互相印证才采信"**——低端机/高负载下单纯循环变慢不再误锁正常玩家（这是改造前的误报点）；
- **绕过**：hook `nativeFridaDetect`→0；或同时压制版本嗅探与"计时+特征印证"两路。
- **静态答案（未检出时）**：seed `20280720` → LCG → `8ac8cc07027b4d6d8bf9cd8003454e71`。flag `FLAG_18_KL26{dusk_hides_the_truth}`。
- *注：`Fatdog_dusk`/`Fatdog_duks` 仅为报告展示，与答案无关。*

### KL27：轻纱覆影（libveil.so · 线程上下文 + 时序交叉）

- **综合判定** `detect_frida = detect_thread_context() || detect_timing_crossref()` —— **OR**。
- **子路①线程上下文**：枚举 `/proc/self/task` 线程名/栈特征，匹配 **frida 专属线程名**（`gum-js-loop`/`pool-frida`/`frida`/`linjector`），已剔除 GLib 的 `gmain`（原匹配 `gmain` 会在普通 GLib 进程误报）；
- **子路②时序交叉**：dlopen 与 malloc 延迟比做交叉验证，9 轮采样以中位数 + 7 轮多数阈值去抖；
- **绕过**：hook 线程名读取 + hook 计时源（`clock_gettime`/`gettimeofday`）喂恒定时延；hook `nativeFridaDetect`→0 照旧可用。
- **静态答案（未检出时）**：seed `20280721` → LCG → `4cc08a01cc4402bc4da28b32cdcd0386`。flag `FLAG_18_KL27{veil_conceals_all}`。
- *注：`Fatdog_gauze`/`Fatdog_gauz` 仅为报告展示，与答案无关。*

### KL28：雪落无痕（libsnow.so · signal + TracerPid）

- **综合判定** `detect_frida = detect_signal_handler() || detect_ptrace()` —— **OR**。
- **子路①signal（已修误报）**：先 `sigaction(SIGUSR1, NULL, &old)` 查询是否已被他人预装自定义 handler（Frida 注入常驻 handler 的真实特征）；再自行 `SIG_UNBLOCK` 解除本线程屏蔽、`kill` 自发送 SIGUSR1 并轮询（≤10ms）确认自身 handler 能正常触发。**旧版只 `usleep(1ms)` 不等信号投递，而 ART 线程默认屏蔽 SIGUSR1，导致正常进程 handler 来不及跑就被误判为"被劫持"——现已修复，无 Frida 时稳定报安全。**
- **子路②TracerPid（ptrace）**：读 `/proc/self/status`，只有真实非零 tracer 才算检出；SELinux/seccomp 拒绝不再误报；
- **绕过**：hook `sigaction`/`signal`（让"预装 handler"查询返回 SIG_DFL）或 hook `/proc/self/status` 读取；spawn + early hook 更稳。
- **静态答案（未检出时）**：seed `20280722` → LCG → `8399c59f0bec469884fec6510ce347fc`。flag `FLAG_18_KL28{snow_leaves_no_trace}`。
- *注：`Fatdog_snow`/`Fatdog_sow` 仅为报告展示，与答案无关。*

## 天地秘境 · 天机阁（KL29-30）



> 天机阁目前两关：KL29 自造 TLV 基准帧（检测型），KL30 为真实服务端取数的 Protobuf 二进制协议关——先逆向协议、逐页取数，再提交 1000 个数字总和。

### KL29：暗流涌动（libtide.so · TLV 二进制协议）

**考点**：把"内存指纹"换成**自造 TLV 帧**做基准比对。`libtide.so`（桥 `Ak29`）导出：

- `nativeTlvMagic()`：把运行期构建的 TLV 帧与内置基准比对（魔数 + 长度域），**patch 帧构建代码即失效**；
- `nativePtrace()`：TracerPid 追踪检查（仅真实非零 tracer 判检出）；
- `nativeFridaDetect()`：两路 OR 综合判定；
- `nativeAnswer()` / `nativeStatus()`：答案与详情（status 输出 `TLV帧基准 / TracerPid检测 / combined` 三行）。

**解法**：
1. **检测侧**：hook `nativeFridaDetect`→0（省事）；教学路线是 hook TLV 基准校验入口 + `/proc/self/status` 读取，或 hook `nativeTlvMagic`/`nativePtrace` 出口都改 0；
2. **答案侧**：IDA 看 `compute_answer()`——LCG 伪随机 hex，种子 `20280723` 与 kl24 同构（同一份 `compute_answer` 代码 + seed 不同）；
3. Python 复刻用扶桑树通用脚本的 `lcg_ans(20280723)`。

**答案**：`3cf175a5b2cbf48a392e72f6bf24f1f2`；flag `FLAG_18_KL29{surging_undercurrents}`。真标记 `Fatdog_surge` / 诱饵 `Fatdog_swell`。

**坑位提醒**：别在 TLV 里找现成协议库——这是教学自造帧（结构见 `app/jni/kl29_tlv_reference.h`），先抓包对 hex 再认字段；`nativeFridaDetect` 不受 `nativeAnswer` 影响，提交前无需先过检测（但教学建议先搞懂检测再交）。

### KL30：天机织锦（libloom.so · Protobuf 二进制协议）

**考点**：手写 Protobuf 编解码 + 服务端取数 + HMAC 签名验证，是"协议逆向 + 服务端对抗"的收官。`libloom.so`（桥 `Ck`）导出四个函数：

- `byte[] nativeBuildRequest(page, ts)` → `PageRequest { page: uint32 = 1; ts: uint64 = 2; }`（varint 手编）；
- `boolean nativeVerifyResponse(byte[])` → 解析 `PageResponse { code: uint32 = 1; nums: repeated int32 = 2; sign: bytes = 3; }`，校验 `code==0 && nums 非空`；
- `int[] nativeParseNums(byte[])` → 解出本页数字；
- `int nativeCode(byte[])` → 取响应 `code`；
- `byte[] nativeSign(byte[])` → 取响应末尾 32 字节 HMAC-SHA256 签名（Java `Ck.verifySignature` 用真密钥 `Fatdog_weave` 重算比对）。

**协议还原路线**：
1. 抓包拿请求/响应 hex → `protoc --decode_raw` 或手工按 wire type 拆（varint 字段 1/2，length-delimited 字段 2/3，nums 是 packed repeated int32）；
2. 重建 `.proto` → 用 Python/任意语言复刻 `nativeBuildRequest` 的编码，逐页 POST `https://<host>/api/kl30`；
3. 对拍 `nativeVerifyResponse` 的判定逻辑即可。

**Python 复刻**（先 `python server.py`）：请求体为 `field 1 = page` + `field 2 = ts` 的 varint 序列；服务端返回 `code=0` + 每页 10 个 `repeated int32`（逐条 wire 0 编码）+ 末尾 `sign: bytes = 3`，`sign = HMAC-SHA256(Fatdog_weave, 不含 sign 的响应体字节)`。收集 100 页共 1000 个数求和 = `50567`（`random.Random(20280724).randint(1,100)`，与 `server.py` 的 `KL30_NUMS` 同源），`sha256("50567")` 即通关哈希。

**坑位提醒**：`Ck.verifySignature` 的 HMAC 密钥就是 so 里两个标记之一（另一为 `Fatdog_knit` 诱饵）；响应签名覆盖的是不含 sign 字段的 body 原始字节，服务端与客户端必须保持同一套 canonical 编码，否则验签失败。flag `FLAG_18_KL30{heavenly_loom}`。

## 天地秘境 · 碧落天（KL36-40）

> 碧落天五关围绕**真实 Flutter 产物**（`lib/arm64-v8a/libapp.so`、`libflutter.so`、`assets/flutter_assets/`）逆向：KL36 识别 + Dart AOT 快照对象池（MD5 签名），KL37 AOT 代码还原 + `--obfuscate` 混淆对抗（AES-128-ECB），KL38 Flutter TLS 证书固定（BoringSSL）绕过，KL39 dart:ffi 双向往调 + 密钥分片，KL40 综合收官。工具链：Blutter / reFlutter / Frida / IDA·Ghidra / radare2。产物由 `tools/flutter_probe/`（Dart 源）+ `tools/build_flutter_artifacts.py` 生成（本机 Flutter 3.47.5 / Dart 3.13.4，走国内镜像）。

### KL36：云中锦书（真实 Flutter 产物 · Dart AOT 快照对象池 · MD5）

**本关产物**：APK 里带了**真实的 Flutter 产物**——`lib/arm64-v8a/libapp.so`（Dart AOT 快照，业务代码所在）、`lib/arm64-v8a/libflutter.so`（引擎，含 Dart VM / BoringSSL / Skia）、`assets/flutter_assets/`。主 App 只是宿主，题眼在载荷里。

**一、识别与版本指纹**

```bash
unzip -l target.apk | grep -E "(libflutter|libapp|flutter_assets|kernel_blob)"
# 命中 libflutter.so + libapp.so + flutter_assets/ → 判定为 Flutter 应用
strings lib/arm64-v8a/libflutter.so | grep -E "^[0-9]+\.[0-9]+\.[0-9]+"   # Flutter/Dart 版本
```

> `jadx` 打开只会看到一层空壳（一个类 + `LoadLibrary("app")`）——Dart 业务代码不在 DEX 里。

**二、静态路线（主推）：Blutter 解快照对象池**

```bash
git clone https://github.com/worawit/blutter && cd blutter
python3 blutter.py <dir>/libapp.so <dir>/libflutter.so ./out
# out/asm/     → 带符号注释的汇编（Dart 库名/函数名已恢复）
# out/pp.txt   → 对象池 dump（字符串常量都在这里）
# out/objs.txt → 对象清单            out/blutter_frida.js → Frida hook stub
grep -n "Fatdog_" out/pp.txt        # 真钥 Fatdog_scroll / 诱饵 Fatdog_roll
```

> Blutter 需要**与目标一致的 Dart SDK 版本**（它从 libflutter.so 自动检测；失败时可 `--dart-version X.Y.Z_android_arm64`）。本关产物由 **Flutter 3.47.5 / Dart 3.13.4** 构建。

**三、动态路线**：`frida -U -f com.fatdog.reverse -l out/blutter_frida.js`，在 Blutter 恢复出的 Dart 函数地址上打点，直接观察 (page, ts, sign)。

**四、签名口径（本关只有一个摘要原语：MD5，不用 HMAC）**

```
sign = md5("page=<page>&ts=<ts>&k=<KEY>")
```

**五、Python 复刻**

```python
import hashlib, requests, time
KEY = "Fatdog_scroll"                     # 真钥（诱饵 Fatdog_roll → 服务端 403）
def sign(page, ts):
    return hashlib.md5(f"page={page}&ts={ts}&k={KEY}".encode()).hexdigest()
ts = int(time.time())
total = 0
for p in range(1, 101):
    r = requests.get(f"https://<host>/api/kl36?page={p}&ts={ts}&sign={sign(p, ts)}", verify=False)
    total += sum(r.json()["nums"])
print(total)                              # 49495
```

对拍值：`sign(1, 1787013761) = 7299ee3ec8e2da29f775da0094ad2044`

**答案**：1000 个数求和 **49495**，`sha256("49495")` = `f13984c09b7e1be91122083721a200d57fc1e211980760643c5f5992e19d8312`。flag `FLAG_18_KL36{cloud_letter_unrolled}`。真标记 `Fatdog_scroll` / 诱饵 `Fatdog_roll`。

**六、兜底路线**

宿主侧伴生 so（`FlutterBridge`）在运行时**优先从 `libapp.so` 的对象池读密钥**（搜哨兵 `FDK36|`），读不到才退回镜像常量（异或藏匿）。所以直接逆伴生 so 也能拿到同一把钥——但那就绕开了本关想练的 Flutter 载荷分析。

**坑位提醒**：
- 认准 `arm64-v8a`；拿错架构的 libapp.so，Blutter 会解析失败；
- 对象池里的字符串是**明文**（Flutter 混淆只改符号名、不加密字符串），但**诱饵只差一个字母**，用错即 403；
- 别指望 Java 层 hook 找路径——Dart 逻辑不在 DEX 里。

### KL37：风中鸢尾（真实 Flutter 产物 · AOT 代码还原 + 混淆对抗 · AES-128-ECB）

**与 KL36 的差别**：同一份 Flutter 载荷，但**符号名被 `--obfuscate` 抹掉**（类/函数变成 `a.b()`），
并且**密钥被拆成两瓣分别存放**——`strings` 只能看到半截。

**一、确认混淆**

```bash
python3 blutter.py <dir>/libapp.so <dir>/libflutter.so ./out
# out/asm/ 里符号已成 a.b()；out/pp.txt 仍是字符串对象池（**混淆不加密字符串**）
grep -n "Fatdog" out/pp.txt      # 只出半截：Fatdog_
grep -n "kite"  out/pp.txt       # 抓不到——第二瓣不是字符串
```

**二、找第二瓣**

第二瓣以**码元数组**存在对象池里（整数数组，不在字符串区）。在 Blutter 的 `objs.txt`（对象清单）
里能找到一个长度 4 的整数数组 `[0x6b, 0x69, 0x74, 0x65]`，用 `String.fromCharCodes` 还原即 `kite`。
两瓣拼接：`Fatdog_` + `kite` = `Fatdog_kite`。

**三、定位业务函数（符号已失）**

在 `asm/` 里按调用链找：谁引用了池里的 `page=` 模板、谁调用了 AES 的初始化/轮函数。
定位到之后确认它对每页参数做了什么。

**四、加密口径（本关只有一种对称加密，无摘要、无 HMAC）**

```
enc = AES-128-ECB-PKCS7(key, "page=<page>&ts=<ts>")   # key = "Fatdog_kite" 补零到 16B
```

对拍值：`enc(1, 1787013761) = 090bc733f1ed59870c72957a2d3fd8fc97d41e467b8d9eb8fe880c4a20682d35`

**五、Python 复刻**

```python
from Crypto.Cipher import AES
import requests, time
KEY = b"Fatdog_kite" + b"\x00" * 5          # 补零到 16 字节
def enc(page, ts):
    pt = f"page={page}&ts={ts}".encode()
    pad = 16 - len(pt) % 16
    return AES.new(KEY, AES.MODE_ECB).encrypt(pt + bytes([pad]) * pad).hex()
ts = int(time.time()); total = 0
for p in range(1, 101):
    r = requests.get(f"https://<host>/api/kl37?page={p}&ts={ts}&enc={enc(p, ts)}", verify=False)
    total += sum(r.json()["nums"])
print(total)                                 # 49958
```

**答案**：1000 个数求和 **49958**，`sha256("49958")` = `1a8c6e655a3eaa77a3c989aa78847e5fc85c223dc4d6d61b96175329b8f3d81c`。
flag `FLAG_18_KL37{iris_in_the_wind}`。真标记 `Fatdog_kite` / 诱饵 `Fatdog_sail`。

**坑位提醒**：
- 混淆只改符号，**字符串仍在对象池**——别以为 obfuscate 之后就没戏了；
- 第二瓣不是字符串，`strings` / 字符串区抓不到，要在对象池的**数组**里认出来；
- 诱饵 `Fatdog_sail` 也在池里，用错 → 服务端解出乱码 → 403；
- 同样认准 `arm64-v8a` 的载荷；
- 宿主伴生 so 走的是**镜像实现**（同样两瓣拼接），逆 so 是兜底路线。

### KL38：雾里观花（真实 Flutter 产物 · BoringSSL 证书固定绕过 · AES-128-CBC + SHA-256）

**本关产物**：与前两关共用同一份真实 Flutter 载荷（`lib/arm64-v8a/libapp.so` / `libflutter.so` / `assets/flutter_assets/`）。本关**题眼是 TLS 证书固定**——Flutter 自带网络栈，既不认系统 CA，也不认 Java 的 TrustManager。

**一、为什么"装证书 / hook OkHttp"都没用**

`dart:io` 的 `HttpClient` 在 Android 上**不走 Java 的 `javax.net.ssl`**，它把 **BoringSSL** 直接编进 `libflutter.so`；证书链校验的入口是 `ssl_crypto_x509_session_verify_cert_chain()`（源码 `ssl/ssl_x509.cc`）。所以：

- 把 CA 装进系统信任库 → 无效；
- hook Java 层 `TrustManager` / `OkHttp` → 无效；
- 改 `network_security_config.xml` → 无效。

**二、定位证书固定（三条常用手法）**

1. **字符串交叉引用**（看雪实证手法）：IDA 载入 `libflutter.so`，搜 `[ssl_client]` 等字符串，顺交叉引用回到校验函数；
2. **pattern scan**：取校验函数**首 10+ 字节**，Frida 里 `Memory.scanSync(Module.findBaseAddress('libflutter.so'), size, '<hex>')` 定位，再 `Interceptor.attach(addr, {onLeave: r => r.replace(1)})` 强制放行；
3. **reFlutter**：自动 patch 引擎让证书校验恒真，重打包 + `uber-apk-signer` 重签名。

> ⚠️ Frida 一把梭会被本关的反调试抓到（见下），所以更稳的是**静态 patch** 或**纯 Python 复刻**。

**三、本关的实际落地（把 BoringSSL 那一层用伴生 so 代替）**

宿主 App 不是 Flutter 运行时，因此用**伴生 so `libflutternet.so`**（JNI 桥 `FlutterNet`）站在与 BoringSSL 相同的位置做事：

1. TLS 握手后取**叶子证书 DER** → `SHA256(DER)`；
2. 与 so 内置的 pin（`pin_store::PIN_XOR`，逐字节 `^0x3C` 藏匿）比对；
3. **pin 锁的是"线上证书"**——训练环境是自签 CA，指纹**必然对不上**，于是 App 自己的请求被自己拒掉（报 `pin: certificate mismatch`）。

**结论：不绕过 pinning，一条数据也拿不到。** 这也是本关与 KL36/KL37 最大的不同——前两关"能发请求，只是算不出参数"，本关是"请求根本发不出去"。

**四、算法口径（摘要 + 对称，无 HMAC）**

| 项 | 值 |
|---|---|
| 主密钥 | `Fatdog_haze`（真）/ `Fatdog_fog`（诱饵，服务端 403） |
| AES 密钥 | `SHA256("<主密钥>|aes")` 的前 **16** 字节 |
| 密文 | `enc = AES-128-CBC-PKCS7(aeskey, IV \|\| "page=N&ts=T")` → hex（**前 16 字节是 IV**） |
| 摘要 | `sign = SHA256(enc + "<主密钥>")` 的十六进制前 **16** 位 |
| 请求 | `GET /api/kl38?page=N&ts=T&enc=<hex>&sign=<16hex>` |
| SEED | 20280701（100 页 × 10 数，共 1000 个数） |
| 求和 | **50778**；`SUM_HASH = 5c8a0ad4292040b13934237f5743c7f05cf912dbac123c7faf1d1c9f022b87b9` |
| flag | `FLAG_18_KL38{flower_in_mist}` |

**密钥在载荷里**：`libapp.so` 对象池里的哨兵是整串 `FDK38|Fatdog_haze|END`（`strings` 就能看到；KL38 的难处不在密钥隐藏，而在证书固定）。伴生 so 的读钥顺序同 KL36：**先从 libapp.so 对象池搜 `FDK38|` 取钥，读不到才退镜像常量**。

**五、反调试（评分制，不是单点定罪）**

三个信号各记 1 分，**≥2 分**才判定"被注入"，判定成立即**静默换用诱饵钥**（`Fatdog_fog`）出密文与摘要，服务端解密/验签自然不认 → 403：

1. `/proc/self/status` 的 `TracerPid` 非 0；
2. `/proc/self/maps` 含 `frida` / `gadget` / `gum-js` / `linjector`；
3. 线程名含 `gum-js-loop` / `pool-frida` / `linjector`（**只用 frida 专属名**，`gmain`/`gdbus` 这类通用名不计，避免误报）。

> 之所以用评分制：KL19/KL28 的教训——部分 ROM 的 seccomp 会让单点检测直接误判，把正常玩家锁死。

**六、绕过路线（三条）**

**路线 A：纯复刻（最干净，不碰 App）**
从 `libapp.so` 拿主密钥 → 按上表算 `enc`/`sign` → 自己发请求 → 求和提交。App 里的 pin 校验与反调试都绕过了。

**路线 B：Frida 绕过 pinning（App 内取数）**
```javascript
Java.perform(function () {
  var FN = Java.use('com.fatdog.reverse.FlutterNet');
  // 让证书固定恒通过
  FN.nativeCheckPin.implementation = function (der) { return true; };
});
```
> 只用这一条会被反调试抓到（maps + 线程名 ≥2 分）→ 密文被换成诱饵钥 → 403。
> 所以还要把检测压掉：`Interceptor.attach(Module.findExportByName('libflutternet.so', ...))`
> 或直接 hook 掉 `nativeEnc`/`nativeSign` 返回自己算的值（那就等价于路线 A 了）。

**路线 C：静态 patch 之后重打包**
把 `libflutternet.so` 里 `pin_store::verify` 改成恒 `1`、`guard::tripped` 改成恒 `0`，
`uber-apk-signer` 重签名后安装。

**七、Python 复刻脚本（路线 A，可直接跑）**

```python
# pip install pycryptodome  （或无第三方时改用 server.py 里的 _aes_cbc_decrypt 纯标准库实现）
import hashlib, json, urllib.request
from Crypto.Cipher import AES

HOST = "https://10.0.2.2:8443"          # 真机改 127.0.0.1:8443
KEY  = b"Fatdog_haze"                   # 真主密钥（诱饵 Fatdog_fog 会被 403）
AESKEY = hashlib.sha256(KEY + b"|aes").digest()[:16]

def pkcs7(b):
    p = 16 - len(b) % 16
    return b + bytes([p]) * p

def make_params(page, ts, iv=None):
    iv = iv or os.urandom(16)                       # 真实运行时 IV 随机并前置
    pt = f"page={page}&ts={ts}".encode()
    ct = AES.new(AESKEY, AES.MODE_CBC, iv).encrypt(pkcs7(pt))
    enc = (iv + ct).hex()
    sign = hashlib.sha256(enc.encode() + KEY).hexdigest()[:16]
    return enc, sign

import os, time
total = 0
for page in range(1, 101):
    ts = int(time.time())
    enc, sign = make_params(page, ts)
    url = f"{HOST}/api/kl38?page={page}&ts={ts}&enc={enc}&sign={sign}"
    with urllib.request.urlopen(url, context=SSL_CTX) as r:   # 训练环境需信任自签 CA
        total += sum(json.loads(r.read())["nums"])
print(total)
# 提交 App：sha256(str(total))[:8]
```

> 静态自检对拍值（固定 IV = `00..0f`，用于验证自己的 CBC 实现）：
> - `enc(1, 1787013761) = 000102030405060708090a0b0c0d0e0f7d4dbd188ea323504608cb166b18fad84f00fb5f1c2b0d2fd8c6561bcf0b2366`
> - `sign(1, 1787013761) = 50dd0bc6a11aef2e`
> - `enc(7, 1700000000) = 000102030405060708090a0b0c0d0e0f45d8692b9d51b0d750852f46481ece6d90c61f05a30574a487c3447529a1b83a`

**八、坑位提醒**

- **pin 锁的是线上证书**，训练环境自签必然不匹配——App 里点"取数"必然报 `pin: certificate mismatch`，这是**设计如此**，不是环境坏了；
- 绕过 pinning 后若仍 403，看界面上的「算法自检」——**检测评分 ≥2/2** 说明被反调试抓到，密文已被换成诱饵钥；
- 诱饵 `Fatdog_fog` 与真钥只差后三个字母（`haze` → `fog`），用错即 403；
- IV 是**随机**的且**前置**在密文里，别拿固定 IV 去乘服务端算出的密文；
- 答案同样是 `sha256(str(sum))` 前 8 位 hex，`sum` 为 1000 个数之和。

### KL39：月下独酌（真实 Flutter 产物 · dart:ffi 双向往调 + 密钥分片 · MD5 + AES-128-ECB）

**本关产物**：与前几关共用同一份真实 Flutter 载荷。本关的题眼是 **dart:ffi 边界**——摘要由 Dart 侧算，对称加密交给 C 侧，而**主密钥被掰成两瓣**：一瓣在 Dart 的对象池里，一瓣编在 native so 里。

**一、算法口径（摘要 + 对称，无 HMAC）**

| 项 | 值 |
|---|---|
| 摘要（Dart 侧） | `d = MD5("page=<page>&ts=<ts>")` → **16 字节原始摘要** |
| 主密钥 | 两瓣拼回：`FRAG_DART` + `FRAG_C` = `Fatdog_moon` |
| AES 密钥 | 主密钥补零到 **16** 字节 |
| 密文（native 侧） | `enc = AES-128-ECB-PKCS7(aeskey, d)` → hex（`d` 16B → 补齐 32B → 64 hex 字符） |
| 请求 | `POST /api/kl39`（表单 `page` / `ts` / `enc`） |
| SEED | 20280715（100 页 × 10 数） |
| 求和 | **49978**；`SUM_HASH = 0e84adc50365026b35f3595727df3d7ab5833873247dc9c639675259e08e4eb5` |
| flag | `FLAG_18_KL39{drinking_alone_moonlight}` |

**二、密钥分片（本关的核心设计）**

| 瓣 | 内容 | 在哪 |
|---|---|---|
| `FRAG_DART` | 8 字节 | `libapp.so` **对象池**：哨兵 `FDK39|Fatdog_m|END`（`strings` 只看到前半截） |
| `FRAG_C` | 3 字节 | `libbow.so` 内部（`^0x42` 藏匿） |

拼回后是 `Fatdog_moon`，补零 16 字节作 AES 密钥。**只逆一侧拿不到完整密钥**——这是本关与 KL36/KL38 最大的不同（那两关密钥整条在载荷里）。

**三、dart:ffi 调用点定位（Blutter）**

1. 用 Blutter 解 `libapp.so`：`blutter.py <libapp.so> <flutter_assets>`;
2. 产物里 `asm/` 是带符号的汇编、`pp.txt` 是对象池 dump；
3. 在 `asm/` 里搜 `DynamicLibrary` / `lookupFunction`（本关导出符号名是 **`fd_moon_enc`**），即可定位 Dart→C 的调用点；
4. native 侧 `nm -D libbow.so` 能看到 `fd_moon_enc` 与三个 JNI 方法；
5. 拿到的 `FRAG_DART` 是 `Fatdog_m`（**半截**），要跟 native 里那 3 字节接起来。

**四、Python 复刻脚本（可直接跑）**

```python
import hashlib, json, os, time, urllib.request, urllib.parse
from Crypto.Cipher import AES

HOST   = "https://10.0.2.2:8443"        # 真机改 127.0.0.1:8443
FRAG_DART = b"Fatdog_m"                 # 载荷对象池里那半截
FRAG_C    = b"oon"                      # native 里那半截
KEY16 = (FRAG_DART + FRAG_C + b"\x00" * 16)[:16]

def pkcs7(b):
    p = 16 - len(b) % 16
    return b + bytes([p]) * p

def make_enc(page, ts):
    d = hashlib.md5(f"page={page}&ts={ts}".encode()).digest()   # 16 字节原始摘要
    return AES.new(KEY16, AES.MODE_ECB).encrypt(pkcs7(d)).hex()

total = 0
for page in range(1, 101):
    ts = int(time.time())
    body = urllib.parse.urlencode({"page": page, "ts": ts, "enc": make_enc(page, ts)}).encode()
    with urllib.request.urlopen(urllib.request.Request(HOST + "/api/kl39", data=body),
                                context=SSL_CTX) as r:      # 训练环境需信任自签 CA
        total += sum(json.loads(r.read())["nums"])
print(total)
# 提交 App：sha256(str(total))[:8]
```

> **自检对拍值**（验证自己的实现是否对）：
> - `md5("page=1&ts=1787013761") = eca5d3dcb2dd82e9036ada197f3dcbed`
> - `enc(1, 1787013761) = cffd009355f00094f0cf7a69b5f35c8b74b22287afa36e098a4c282f985d68d6`
> - `enc(7, 1700000000) = 51ece1f3a4e3198dc9ff794b835d3bf074b22287afa36e098a4c282f985d68d6`

**五、动态路线（Frida）**

```javascript
Java.perform(function () {
  var FFI = Java.use('com.fatdog.reverse.FlutterFFI');
  // 直接读 native 出的密文，再用本地复刻的算法对照
  console.log(FFI.nativeEnc(1, 1787013761, FFI.md5Of(1, 1787013761)));
  // 或回到 Dart 侧：hook fd_moon_enc 的返回
  var p = Module.findExportByName('libbow.so', 'fd_moon_enc');
  Interceptor.attach(p, { onLeave: function (r) { console.log(r.readUtf8String()); } });
});
```

**六、坑位提醒**

- `FRAG_DART` 在对象池里只有 **8 字节**（`Fatdog_m`），别以为拿到整条密钥了——剩下 3 字节只在 native 里；
- 摘要传的是 **16 字节原始值**，不是 hex 字符串：写成 `md5(...).hexdigest()` 会得到完全不同的密文；
- 密钥要**补零到 16 字节**（`Fatdog_moon` 只有 11 字节）；
- 诱饵 `Fatdog_star` 与真钥只差第 8 个字母（`m`→`s`），用错即 403；
- 服务端**只比对解密出的摘要**，`enc` 长度必须是 16 的倍数（`d` 16B + PKCS#7 补齐 → 32B）；
- 答案同样是 `sha256(str(sum))` 前 8 位 hex。

### KL40：星河倒影（真实 Flutter 产物 · 综合收官卷 · AES-256-GCM + MD5 + 换钥 AES 解密）

**本关产物**：与前四关共用同一份真实 Flutter 载荷。收官卷把前面几关的手艺叠在一起——**三原语 + 换钥**。

**一、算法口径（三原语叠加，无 HMAC）**

| 环节 | 算法 | 密钥 |
|---|---|---|
| 请求加密 | **AES-256-GCM**（nonce 12B 前置 + ct + **tag 16B**） | `KREQ = SHA256("Fatdog_reflect\|req")`（32 字节） |
| 签名 | **普通 MD5**（非 HMAC） | `sign = md5("page=N&ts=T&enc=<enc>&k=<主标记>")` |
| 响应解密 | **AES-128-CBC**（iv 16B 前置）——**换了一把钥** | `KRESP = SHA256("Fatdog_reflect\|resp")[:16]` |

- 请求 `POST /api/kl40`（表单 `page/ts/enc/sign`），响应 `{"d": "<hex>"}`；
- `enc = hex(nonce(12) ‖ ct ‖ tag(16))`；主标记 `Fatdog_reflect`（诱饵 `Fatdog_echo` → 403）；
- SEED 20280720，1000 个数求和 **52005**；flag `FLAG_18_KL40{galaxy_reflected}`。

**二、三道锁各是什么**

1. **GCM 的完整性**：改动 `ct` 或 `tag` 里任意一个字节，服务端**直接拒收**（不是"解出来乱码"）——这是它与前面 CBC/ECB 关卡最大的不同。
2. **MD5 只是凭据**：普通摘要，明文里夹着主标记，作用是"证明你会算"；它**不提供完整性**，别当成 MAC。
3. **换钥**：回来的数据用**另一把** AES 钥（CBC）锁着。要先意识到"回来的钥和去的那把不是同一把"，再从同一主标记派生响应钥。

**三、密钥与定位**

主标记在 `libapp.so` 对象池：哨兵 `FDK40|Fatdog_reflect|END`（`strings` 直接可见）。两把钥都由它派生：

```
KREQ  = SHA256("Fatdog_reflect|req")        # 32 字节（AES-256）
KRESP = SHA256("Fatdog_reflect|resp")[:16]  # 16 字节（AES-128）
```

Blutter 路线：`blutter.py libapp.so flutter_assets` → 在 `asm/` 里找 GCM 调用点与两处 SHA256 派生；
native 侧 `nm -D librig.so` 能看到 `nativeEnc` / `nativeSign` / `nativeDecryptRsp`。

**四、Python 复刻脚本（可直接跑）**

```python
import hashlib, json, os, time, urllib.request, urllib.parse
from Crypto.Cipher import AES

HOST   = "https://10.0.2.2:8443"          # 真机改 127.0.0.1:8443
MASTER = b"Fatdog_reflect"
KREQ   = hashlib.sha256(MASTER + b"|req").digest()
KRESP  = hashlib.sha256(MASTER + b"|resp").digest()[:16]

total = 0
for page in range(1, 101):
    ts = int(time.time())
    nonce = os.urandom(12)
    c = AES.new(KREQ, AES.MODE_GCM, nonce=nonce)
    ct, tag = c.encrypt_and_digest(f"page={page}&ts={ts}".encode())
    enc = (nonce + ct + tag).hex()
    sign = hashlib.md5(f"page={page}&ts={ts}&enc={enc}&k={MASTER.decode()}".encode()).hexdigest()
    body = urllib.parse.urlencode({"page": page, "ts": ts, "enc": enc, "sign": sign}).encode()
    with urllib.request.urlopen(urllib.request.Request(HOST + "/api/kl40", data=body),
                                context=SSL_CTX) as r:      # 训练环境需信任自签 CA
        d = bytes.fromhex(json.loads(r.read())["d"])
    pt = AES.new(KRESP, AES.MODE_CBC, d[:16]).decrypt(d[16:])   # ← 换钥解密
    total += sum(json.loads(pt[:-pt[-1]])["nums"])
print(total)
# 提交 App：sha256(str(total))[:8]
```

> **自检对拍值**（固定 nonce = `00..0b`，用来验证自己的实现）：
> - `KREQ  = 29242857cf181d625daae8382d884665f181e93300b765d8f6f4697d290ceb6e`
> - `KRESP = 86eb74c2e8e5e1c3be77f62a6396e6ee`
> - `enc(1, 1787013761) = 000102030405060708090a0bfca4e4823b0690e6ae7f0e72f523021cfb493137d5361668ad86cb7bbfbac307efb927b4`
> - `sign(1, 1787013761) = d2b77110728e5bb259dd144b8452e021`

**五、其它层（与前面几关同源）**

- **识别 / 快照还原**：Blutter（`pp.txt` 对象池 + `asm/` 符号化汇编）；
- **BoringSSL pinning**：本关仍只信任项目自签 CA，抓包同其余 HTTPS 关（Charles 导入 `certs/ca.crt` + `ca.key`）；
- **反调试**：评分制（`TracerPid` / maps 的 frida 特征 / frida 专属线程名，各 1 分，**≥2 才判定**），判定成立即静默改用诱饵钥 `Fatdog_echo` → 服务端 403。

**六、坑位提醒**

- **GCM 与 CBC 的差别**：GCM 改一字节直接**拒收**，CBC 是"解出来乱码"——别混为一谈；
- **MD5 不是 MAC**：只做凭据，真正防篡改的是 GCM 的 tag；
- **nonce 12 字节、iv 16 字节**都随机且**前置**在密文之前，别拿固定值去解服务端回来的密文；
- 请求钥 **32 字节**、响应钥 **16 字节**——长度不同是刻意的（AES-256 / AES-128）；
- 诱饵 `Fatdog_echo` 与真钥只差后半截，用错即 403；
- 答案同样是 `sha256(str(sum))` 前 8 位 hex。

**七、静态 patch / 重打包**

```text
apktool d FatdogReverse.apk -o out
# 改 librig.so：把 guard::tripped 改成恒 0（或直接把 nativeDecryptRsp 的钥换掉）
apktool b out -o rebuilt.apk
zipalign -f 4 rebuilt.apk aligned.apk
apksigner sign --ks keystore/debug.keystore --ks-key-alias androiddebugkey \
        --ks-pass pass:android --key-pass pass:android --out patched.apk aligned.apk
adb install -r patched.apk
```

### 附 2 · Frida 通用速查

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

# L10-14：明文/种子/密钥都藏在代码里，摘要只做指纹；Hook 观察或还原即可，不要只 return true 硬通
# 其他改判型关卡按题面/解法节操作，具体入口见各关正文
```



### 附 3 · flag 速查表（全量 L1-47 + KL1-30 + KKL1-5）


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
| 15 | `FLAG_18_L15{thousand_number_sum}` |
| 16 | `FLAG_18_L16{rc4_stream_encrypted}` |
| 17 | `FLAG_18_L17{sm4_sm3_form}` |
| 18 | `FLAG_18_L18{rsa_des_form}` |
| 19 | `FLAG_18_L19{obfuscated_aes_hmac}` |
| 20 | `FLAG_18_L20{ads_are_gone}` |
| 21 | `FLAG_18_L21{tls_custom_trust}` |
| 22 | `FLAG_18_L22{okhttp_certificate_pinner}` |
| 23 | `FLAG_18_L23{webview_ssl_error}` |
| 24 | `FLAG_18_L24{anti_hook_pin_swap}` |
| 25 | `FLAG_18_L25{native_jni_verify}` |
| 26 | `FLAG_18_L26{mutual_tls_client_cert}` |
| 27 | `FLAG_18_L27{capture_then_replicate}` |
| 28 | `FLAG_18_L28{runtime_decoded_key}` |
| 29 | `FLAG_18_L29{register_natives_caught}` |
| 30 | `FLAG_18_L30{nameless_dispatch}` |
| 31 | `FLAG_18_L31{cross_layer_key}` |
| 32 | `FLAG_18_L32{silent_poison_defused}` |
| 33 | `FLAG_18_L33{crc_guard_bypassed}` |
| 34 | `FLAG_18_L34{guixu_all_in_one}` |
| 35 | `FLAG_18_L35{sbox_tells_all}` |
| 36 | `FLAG_18_L36{base64_is_not_encryption}` |
| 37 | `FLAG_18_L37{avalanche_hides_the_blood}` |
| 38 | `FLAG_18_L38{puppet_line_attached}` |
| 39 | `FLAG_18_L39{swap_the_argument}` |
| 40 | `FLAG_18_L40{secret_field_exposed}` |
| 41 | `FLAG_18_L41{triple_gate_broken}` |
| 42 | `FLAG_18_L42{persistence_is_power}` |
| 43 | `FLAG_18_L43{mirror_tells_true}` |
| 44 | `FLAG_18_L44{forged_no_more}` |
| 45 | `FLAG_18_L45{self_read_beats_pm}` |
| 46 | `FLAG_18_L46{key_derived_from_cert}` |
| 47 | `FLAG_18_L47{guard_matrix_crc_aes}` |



**天地秘境（KL/KKL）**


| 关卡 | flag |
|---|---|
| KL1 | `FLAG_18_KL1{gate_of_kunlun}` |
| KL2 | `FLAG_18_KL2{thunder_rod}` |
| KL3 | `FLAG_18_KL3{raven_bridge_crossed}` |
| KL4 | `FLAG_18_KL4{glacier_crossed_clean}` |
| KL5 | `FLAG_18_KL5{summit_reached}` |
| KL6 | `FLAG_18_KL6{ice_seal_broken}` |
| KL7 | `FLAG_18_KL7{soul_box_shattered}` |
| KL8 | `FLAG_18_KL8{spring_eye_awake}` |
| KL9 | `FLAG_18_KL9{dipper_veil_lifted}` |
| KL10 | `FLAG_18_KL10{myriad_as_one}` |
| KL11 | `FLAG_18_KL11{nop_the_guard}` |
| KL12 | `FLAG_18_KL12{hook_the_seal}` |
| KL13 | `FLAG_18_KL13{crc_cannot_protect}` |
| KL14 | `FLAG_18_KL14{mesh_of_three}` |
| KL15 | `FLAG_18_KL15{all_methods_converge}` |
| KL16 | `FLAG_18_KL16{husk_shed}` |
| KL17 | `FLAG_18_KL17{class_refilled}` |
| KL18 | `FLAG_18_KL18{method_rewoven}` |
| KL19 | `FLAG_18_KL19{debug_beaten}` |
| KL20 | `FLAG_18_KL20{legu_unboxed}` |
| KL21 | `FLAG_18_KL21{leaf_hears_the_wind}` |
| KL22 | `FLAG_18_KL22{shadow_leaves_no_trace}` |
| KL23 | `FLAG_18_KL23{mirror_shows_true_face}` |
| KL24 | `FLAG_18_KL24{ice_mirror_catches_all}` |
| KL25 | `FLAG_18_KL25{mist_locks_the_ears}` |
| KL26 | `FLAG_18_KL26{dusk_hides_the_truth}` |
| KL27 | `FLAG_18_KL27{veil_conceals_all}` |
| KL28 | `FLAG_18_KL28{snow_leaves_no_trace}` |
| KL29 | `FLAG_18_KL29{surging_undercurrents}` |
| KL30 | `FLAG_18_KL30{heavenly_loom}` |
| KKL1 | `FLAG_18_KKL1{abyss_of_mystery}` |
| KKL2 | `FLAG_18_KKL2{tomb_of_myriad_blades}` |
| KKL3 | `FLAG_18_KKL3{valley_of_the_sentinel}` |
| KKL4 | `FLAG_18_KKL4{tower_of_the_sealed}` |
| KKL5 | `FLAG_18_KKL5{ascension_of_the_immortals}` |
| KL36 | `FLAG_18_KL36{cloud_letter_unrolled}` |
| KL37 | `FLAG_18_KL37{iris_in_the_wind}` |
| KL38 | `FLAG_18_KL38{flower_in_mist}` |
| KL39 | `FLAG_18_KL39{drinking_alone_moonlight}` |
| KL40 | `FLAG_18_KL40{galaxy_reflected}` |

---

## 天地秘境 · 须弥界（KL41+）

> 须弥界覆盖 Hybrid App / H5 壳逆向：WebView 承载 H5、JSBridge 注入定位、H5 资源加密、JS 层加密逻辑还原、bridge 协议与签名拦截。（原 RN / Weex / Uni-app 方向已废除，编号沿用 KL41-KL45。）

### JS 逆向通用流程（KL42 / KL43 / KL44 的混淆页都适用）

> 这三关的前端脚本都用 `javascript-obfuscator`（obfuscator.io 同款）混淆：字符串进“字符串数组”并按 **RC4 编码**、控制流平坦化、变量名十六进制化。还原套路一致，先吃透这一节，再看各关细节。

**第 1 步 · 拿到页面源码**
- 静态：解包 APK 取 `assets/h5/*.html`（KL42 的是 RC4 密文，先按该关“资源层”解容器）。
- 动态（可互相印证）：Frida 挂 WebView 载入点直接打源码：
```javascript
Java.perform(function () {
    var W = Java.use("android.webkit.WebView");
    W.loadDataWithBaseURL.overload('java.lang.String','java.lang.String','java.lang.String','java.lang.String','java.lang.String')
     .implementation = function (b, h, m, e, d) { console.log("[html]\n" + h); return this.loadDataWithBaseURL(b, h, m, e, d); };
    W.loadUrl.overload('java.lang.String').implementation = function (u) { console.log("[url] " + u); return this.loadUrl(u); };
});
```
  也可以等 `onPageFinished` 后 `evaluateJavascript("document.documentElement.outerHTML")` 回读。

**第 2 步 · 认出混淆**
- 变量名形如 `_0x4f2a`；代码里有**一个大字符串数组** `['...','...']`；
- 到处是 `_0x4f2a(0x12)` 这种“取数组第 N 项”的调用 → obfuscator.io 的 **stringArray**；
- 数组元素是 **base64 串**（如 `ZXZhbA==`）→ 用了 `stringArrayEncoding: ['rc4']`，另有一小段解码函数做 base64 → RC4 → 明文。

**第 3 步 · 反混淆（三选一）**
1. **一键工具**：把整段 `<script>` 贴进 **de4js**（在线）/ obfuscator 配套还原脚本，勾 “String Array” + “String Array Encoding: RC4”，直接出明文。
2. **格式化后手工**：`js-beautify a.js > a.pretty.js`，找到字符串数组与解码函数，把 `_0x4f2a(0x12)` 逐处替换成明文（可写个 Node 小脚本自动跑）。
3. **动态偷明文**：不还原也能干活——在页内 hook 取串函数打印返回值，或直接 hook 你关心的那处（见各关）。

**第 4 步 · 找密钥与算法**
- 明文里搜 `page=` / `&ts=` / `cmd=` 这类拼接片段，往上追它的输入变量 → 就是密钥常量；
- 认算法：**RC4** 有“256 次 `S[i]=i` 初始化 + 双指针交换”的典型结构；**HMAC-SHA256** 有 64 个 32 位常量 `0x428a2f98, 0x71374491, …` 与 `0x36 / 0x5c` 两个 pad 常量。

**第 5 步 · Python 复刻并对拍**
- 复刻后在真机抓一次实际请求，比对自己的 enc/sign 与 App 发出的**是否逐字节相同**（ts 取同值）。

### KL41：浅滩拾贝（libh5shell.so · H5 壳 / JSBridge 注入定位）

**考点**：WebView 加载本地 H5 → Java 侧 `addJavascriptInterface` 注入 bridge 对象 → bridge 的 `@JavascriptInterface` 方法（getToken/sign/verify/version）→ 真钥匙藏在 `libh5shell.so` 的异或数组里、运行时才拼出 → HMAC-SHA256 签名。

**难点陈述**：
- 签不是前端自算的：H5 通过 `window.FatdogBridge` 这座桥向 native 要签。
- 真钥匙不在 Java/DEX：诱饵类 `ShellKit` 里那句 `Fatdog_drift` 是假的，服务端会 403。
- 要签名，先摸清桥——注入对象名、暴露的方法、以及 so 里那张异或数组。

**协议**：GET `https://10.0.2.2:8443/api/kl41?page=N&ts=T&sign=HMAC-SHA256`

**路线一 · 静态复刻（Python，最稳）**：
先从 so 的异或数组还原真钥 `Fatdog_surf`（字节串 `{122,93,72,88,83,91,99,79,73,78,90}` 逐字节 `^0x3C`）：
```python
import requests, time, hmac, hashlib

KEY = b"Fatdog_surf"          # libh5shell.so 异或数组运行时还原所得
BASE = "https://10.0.2.2:8443"
s = requests.Session()
s.verify = False

total = 0
for page in range(1, 101):
    ts = int(time.time())
    msg = f"page={page}&ts={ts}"
    sign = hmac.new(KEY, msg.encode(), hashlib.sha256).hexdigest()
    r = s.get(f"{BASE}/api/kl41", params={"page": page, "ts": ts, "sign": sign})
    total += sum(r.json()["nums"])

print(f"sum  = {total}")                                       # 51585
print(f"hash = {hashlib.sha256(str(total).encode()).hexdigest()}")
```

**路线二 · Frida 动态**：
```javascript
Java.perform(function () {
    // 1) 定位注入点：谁被 addJavascriptInterface 注进了 WebView、叫什么名字
    var WebView = Java.use("android.webkit.WebView");
    WebView.addJavascriptInterface.implementation = function (obj, name) {
        console.log("[bridge] " + name + " -> " + obj.getClass().getName());
        return this.addJavascriptInterface(obj, name);
    };
    // 2) 直接借桥取签名 / token / 方法表（密钥不进 Java，native 运行时从 so 拼）
    var H5Shell = Java.use("com.fatdog.reverse.H5Shell");
    console.log("methods = " + H5Shell.nativeGetBridgeMethods());
    console.log("token   = " + H5Shell.nativeToken());
    H5Shell.nativeSign.implementation = function (page, ts) {
        var r = this.nativeSign(page, ts);
        console.log("sign(" + page + ", " + ts + ") = " + r);
        return r;
    };
});
```

**答案**：100 页共 1000 个数求和 = **51585**，提交该加和即通关（App 内比对 `sha256(str(sum)) == SUM_HASH`）。flag `FLAG_19_KL41{shallow_shell_found}`。真钥 `Fatdog_surf` / 诱饵 `Fatdog_drift`。

**坑位**：
- bridge 对象名 / 方法：`FatdogBridge` / `getToken|sign|verify|version`；注入类 = `surfActivity$ShellBridge`。
- 诱饵类 `ShellKit` 里 `Fatdog_drift` 是明文假钥，用它签名服务端 403——别被它带偏。
- SEED_KL41=20280901，启动日志会打印 `KL41=51585`；加和随 SEED 变化。

### KL42：沙中藏贝（libwebvault.so · H5 资源加密 + JS 层加密）

**考点**：H5 资源（HTML + 前端 JS）不是明文躺在 assets 里——它以 RC4 加密容器 `assets/h5/vault_kl42.bin` 存放，钥匙藏在 `libwebvault.so` 的异或数组；解密出的前端 JS 又被 obfuscator 混淆，**真正的签名密钥藏在 JS 里**（不在 so、不在 Java）。

**协议**：GET `https://10.0.2.2:8443/api/kl42?page=N&ts=T&sign=HMAC-SHA256`

**两层拆解**：
1. **资源层**：`libwebvault.so` 用 RC4 解容器，钥匙 = `Fatdog_vault`（异或数组 `{122,93,72,88,83,91,99,74,93,73,80,72}` 逐字节 `^0x3C`）；算法标识 `RC4`（`nativeGetResourceCipher()`）。
2. **JS 层**：解出来的页面里有一段被 javascript-obfuscator 混淆的脚本，签名密钥 = `Fatdog_reef`，算法 = HMAC-SHA256 —— 必须反混淆才能拿到。

**路线一 · 静态复刻（Python）**：
```python
import requests, time, hmac, hashlib

def rc4(key, data):                       # 解资源容器
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(); i = j = 0
    for ch in data:
        i = (i + 1) & 0xFF; j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(ch ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)

html = rc4(b"Fatdog_vault", open("vault_kl42.bin", "rb").read()).decode("utf-8")
# 2) 从页面里抠出被混淆的脚本，反混淆（de4js / js-beautify / 手工还原字符串数组）后得到签名密钥
KEY = b"Fatdog_reef"

BASE = "https://10.0.2.2:8443"
s = requests.Session(); s.verify = False
total = 0
for page in range(1, 101):
    ts = int(time.time())
    sign = hmac.new(KEY, f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()
    total += sum(s.get(f"{BASE}/api/kl42", params={"page": page, "ts": ts, "sign": sign}).json()["nums"])
print("sum =", total)                      # 51229
```

**路线二 · Frida 动态**：
```javascript
Java.perform(function () {
    var WebVault = Java.use("com.fatdog.reverse.WebVault");
    console.log("cipher = " + WebVault.nativeGetResourceCipher());
    // 容器钥匙在 so 里：hook nativeDecryptAsset 直接拿解出来的明文页面
    WebVault.nativeDecryptAsset.implementation = function (enc) {
        var html = this.nativeDecryptAsset(enc);
        console.log("[decrypted html]\n" + html);
        return html;
    };
    // 页面里的签名由 window.fdSign 算；想抓也可以 hook WebView.evaluateJavascript 看调用
});
```

**JS 逆向详解（本关的混淆页）**：
1. 先过**资源层**拿明文页：`html = rc4(b"Fatdog_vault", open("vault_kl42.bin","rb").read())`。
2. 抠出页里 `<script>` 的脚本（约 20KB，清一色 `_0x…` 变量 + 一个大字符串数组）。
3. 反混淆（de4js 勾 RC4 编码；或手工：数组元素是 base64，解码函数里含 `atob` 与 RC4 轮）→ 得到原始逻辑：
```javascript
var SECRET = "Fatdog_reef";
function hmacSha256Hex(key, msg) { /* JS 版 HMAC-SHA256 */ }
function fdSign(page, ts) { return hmacSha256Hex(SECRET, "page=" + page + "&ts=" + ts); }
```
4. 结论：**第一层密钥 = `Fatdog_reef`，算法 = HMAC-SHA256，签名原文 = `page=<N>&ts=<T>`**。
5. Python 复刻：`sign = hmac.new(b"Fatdog_reef", f"page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()`。
6. 动态偷懒：页面里函数挂在 `window.fdSign`，直接 `evaluateJavascript("window.fdSign(1, 1700000000)")` 就能拿一份真签；或 hook `WebVault.nativeDecryptAsset` 拿明文页。

**答案**：100 页共 1000 个数求和 = **51229**，提交该加和即通关。flag `FLAG_19_KL42{sand_hidden_shell}`。真钥 `Fatdog_reef`（在混淆 JS 里）/ 诱饵 `Fatdog_shore`（服务端 403）。

**坑位**：
- 只解容器、不反混淆，拿不到 `Fatdog_reef`——JS 层是独立的一关活儿。
- 诱饵 `Fatdog_shore` 出现在 so 与 `BeachKit`（诱饵类）里，签了会被拒。
- SEED_KL42=20280902，启动日志打印 `KL42=51229`。
- 容器由 `tools/gen_kl42.py` 生成（明文 JS → ob 混淆 → 包 HTML → RC4），可复现。

### KL43：桥上听风（libjsbridge.so · JSBridge 协议逆向 + JS 侧消息签名）

**考点**：页面与 native 之间走一套 JSBridge 协议——消息是 `{cmd, page, ts, sign}`，**sign 由页面脚本（JS 层）计算**；native 侧持有一张 cmd→handler 的分发表，按表分发。要通关得：① 抓 bridge 消息 ② 还原 dispatch 表 ③ 反混淆 JS 拿签名密钥 ④ 重放。

**协议**：POST `https://10.0.2.2:8443/api/kl43`，表单 `cmd=q&page=N&ts=T&sign=HMAC-SHA256`

**桥的三件套**：
- 消息：`{"cmd":"q","page":N,"ts":T,"sign":"<hex>"}`，`sign = HMAC(Fatdog_coral, "cmd=q&page=N&ts=T")`。
- dispatch 表（native）：`{"q":"query","v":"version","p":"ping"}` —— `nativeHandle(msg)` 按表分发，认不出返回 `unknown`。
- 真钥 `Fatdog_coral` 在 `assets/h5/bridge_kl43.html` 内被混淆的 JS 里；诱饵 `Fatdog_tidepool`（在 `TideKit` 里）。

**路线一 · 静态复刻（Python）**：
```python
import requests, time, hmac, hashlib
# 1) 从 assets/h5/bridge_kl43.html 抠出被混淆的脚本，反混淆（de4js 等）后得到消息密钥
KEY = b"Fatdog_coral"
BASE = "https://10.0.2.2:8443"
s = requests.Session(); s.verify = False
total = 0
for page in range(1, 101):
    ts = int(time.time())
    sign = hmac.new(KEY, f"cmd=q&page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()
    r = s.post(f"{BASE}/api/kl43", data={"cmd": "q", "page": page, "ts": ts, "sign": sign})
    total += sum(r.json()["nums"])
print("sum =", total)                     # 51155
```

**路线二 · Frida 动态**：
```javascript
Java.perform(function () {
    var JB = Java.use("com.fatdog.reverse.JsBridge");
    console.log("dispatch table = " + JB.nativeGetDispatchTable());
    // 抓 bridge 消息（含 JS 侧算出的 sign）
    JB.nativeHandle.implementation = function (msg) {
        console.log("[bridge msg] " + msg);
        return this.nativeHandle(msg);
    };
});
```

**JS 逆向详解（本关的混淆页）**：
1. 页面 `assets/h5/bridge_kl43.html` **不加密**，直接抠 `<script>` 反混淆即可（套用「JS 逆向通用流程」）。
2. 还原后得到：
```javascript
var MSG_KEY = "Fatdog_coral";
function buildMsg(cmd, page, ts) {
    var sign = hmacSha256Hex(MSG_KEY, "cmd=" + cmd + "&page=" + page + "&ts=" + ts);
    return JSON.stringify({ cmd: cmd, page: page, ts: ts, sign: sign });
}
function fdMsg(page, ts) { return buildMsg("q", page, ts); }
```
3. 结论：**密钥 = `Fatdog_coral`，算法 = HMAC-SHA256，签名原文 = `cmd=q&page=<N>&ts=<T>`**（注意带 `cmd=` 前缀，别漏）。
4. Python 复刻：`sign = hmac.new(b"Fatdog_coral", f"cmd=q&page={page}&ts={ts}".encode(), hashlib.sha256).hexdigest()`。
5. 动态：hook `WebView.evaluateJavascript` 看 App 取到的消息 JSON（含 sign）；或 `Java.use("…JsBridge").nativeGetDispatchTable()` 直接拿 cmd 分发表。

**答案**：100 页共 1000 个数求和 = **51155**。flag `FLAG_19_KL43{wind_on_the_bridge}`。真钥 `Fatdog_coral`（混淆 JS 里）/ 诱饵 `Fatdog_tidepool`（403）。

**坑位**：
- sign 的原文是 `cmd=q&page=N&ts=T`（不是 KL41 的 `page&ts`）——得从被混淆的脚本里看清。
- 篡改 cmd 会被本地 dispatch 拦下（返回 `unknown`）——重放时别乱改指令。
- SEED_KL43=20280903，启动日志打印 `KL43=51155`。

### KL44：暗流涌动（libsignbridge.so · JSBridge 签名拦截 + JS 层加密）

**考点（双层）**：第一层在**前端脚本**里——用 RC4 把明文参数搅成密文 `enc`（密钥藏在混淆 JS）；第二层在 **native**——对 `page=..&ts=..&enc=..` 再做一次 HMAC-SHA256（密钥藏在 so）。两层钥不同、算法不同，缺一层都取不到数。另加 **ptrace + maps 反调试**：判定被调试则改用诱饵钥签名。

**协议**：POST `https://10.0.2.2:8443/api/kl44`，表单 `page=N&ts=T&enc=<hex>&sign=<hex>`

**两层拆解**：
| 层 | 做什么 | 钥（在哪） | 算法 |
|---|---|---|---|
| 第一层 | `enc = RC4(明文 "page=N&ts=T")` | `Fatdog_pearl`（混淆 JS 里） | RC4 |
| 第二层 | `sign = HMAC(明文 + enc)` | `Fatdog_surge`（so 里，异或藏） | HMAC-SHA256 |

- 签名原文：`page=<N>&ts=<T>&enc=<enc>`。
- 诱饵钥 `Fatdog_foam`（so 的诱饵数组 + `FoamKit`），签了 403。
- 反调试：三路信号（TracerPid / ptrace 失败 / maps 含 frida|gdb|lldb|gum-js）各记 1 分，**≥2 才判定**（评分制防误杀）；判定成立 → 用诱饵钥签名。

**路线一 · 静态复刻（Python）**：
```python
import requests, time, hmac, hashlib

def rc4(key, data):                                   # 第一层：JS 侧那把钥的算法
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(); i = j = 0
    for ch in data:
        i = (i + 1) & 0xFF; j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(ch ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)

JSKEY = b"Fatdog_pearl"     # 第一层钥（从混淆 JS 还原）
NKEY  = b"Fatdog_surge"     # 第二层钥（从 so 的异或数组还原）
BASE  = "https://10.0.2.2:8443"
s = requests.Session(); s.verify = False

total = 0
for page in range(1, 101):
    ts = int(time.time())
    enc = rc4(JSKEY, f"page={page}&ts={ts}".encode()).hex()           # 第一层
    sign = hmac.new(NKEY, f"page={page}&ts={ts}&enc={enc}".encode(),
                    hashlib.sha256).hexdigest()                        # 第二层
    r = s.post(f"{BASE}/api/kl44", data={"page": page, "ts": ts, "enc": enc, "sign": sign})
    total += sum(r.json()["nums"])
print("sum =", total)                                  # 50424
```

**JS 逆向详解（本关的第一层）**：
1. 页面 `assets/h5/sign_kl44.html` 不加密，直接抠 `<script>`（约 8.7KB，`_0x…` 变量 + 大字符串数组，base64 元素）→ 套用「JS 逆向通用流程」反混淆。
2. 还原后得到：
```javascript
var ENC_KEY = "Fatdog_pearl";
function rc4(key, data) { /* 256 初始化 + 双指针交换 */ }
function fdEnc(page, ts) { return hex(rc4(s2b(ENC_KEY), s2b("page=" + page + "&ts=" + ts))); }
```
3. 结论：**第一层钥 = `Fatdog_pearl`，算法 = RC4，明文 = `page=<N>&ts=<T>`，输出 hex**。
4. 只要钥和算法对上，`enc` 逐字节可复现（本关 `enc(1,1787013761) = 10505b4d47fd3c00d52415a5b364f140791b705b`）。
5. 动态：页面函数挂在 `window.fdEnc`，`evaluateJavascript("window.fdEnc(1, 1700000000)")` 直接拿密文；或 hook `SignBridge.nativeBridgeSign` 看 native 入参（就是 enc）。

**路线二 · Frida 动态**：
```javascript
Java.perform(function () {
    var SB = Java.use("com.fatdog.reverse.SignBridge");
    console.log("guard = " + SB.nativeStatus());            // 反调试自检（只读）
    // 第二层签名：入参就是第一层的密文 enc
    SB.nativeBridgeSign.implementation = function (page, ts, enc) {
        var r = this.nativeBridgeSign(page, ts, enc);
        console.log("page=" + page + " ts=" + ts + " enc=" + enc + "\n -> sign=" + r);
        return r;
    };
});
```

**反调试绕过要点**：本关反调试是**评分制**（≥2 分才判定）——正常设备最多命中 1 项，不会误杀。挂了调试器时 TracerPid 与 ptrace 会同时中招。想绕过：hook `nativeStatus` 只读不判胜（无用），真正要改的是判定结果——用 Frida 拦 `SignBridge.nativeBridgeSign` 并在**未被调试的进程**里算（或直接静态复刻两层）。**注意**：`nativeStatus()` 只做只读展示，不参与判胜、也不吐钥。

**答案**：100 页共 1000 个数求和 = **50424**。flag `FLAG_19_KL44{undertow_surging}`。真钥 `Fatdog_pearl`（JS 层）/ `Fatdog_surge`（native 层）；诱饵 `Fatdog_foam`（403）。

**坑位**：
- 两层**都要**还原：只解 JS 层没 native 钥、只逆 so 没 JS 钥，都拿不到数。
- `sign` 的原文里**含 `enc`**（`page=..&ts=..&enc=..`），enc 变了 sign 也得重算。
- SEED_KL44=20280904，启动日志打印 `KL44=50424`。

### KL45：深渊合璧（libhybrid.so · 综合收官卷：JS 层 AES + native 普通 MD5）

**考点（收官综合）**：须弥界收官卷，把前四关手段收束成两道锁——第一层在**前端脚本**里，用 **AES-128-ECB** 把明文参数加密成密文 `enc`（密钥藏在 ob 混淆的 JS）；第二层在 **native**，对「真钥 + 明文参数 + 密文」取一次**普通 MD5** 作为签名。另加 **ptrace + maps 反调试**（评分制）：判定被调试则改用诱饵钥，签了也白签。

**协议**：POST `https://10.0.2.2:8443/api/kl45`，表单 `page=N&ts=T&enc=<hex>&sign=<hex>`

**两层拆解**：

| 层 | 做什么 | 钥（在哪） | 算法 |
|---|---|---|---|
| 第一层 | `enc = AES-ECB(明文 "page=N&ts=T")` | `Fatdog_abyss`（混淆 JS 里，补零到 16B） | AES-128-ECB + PKCS#7 |
| 第二层 | `sign = MD5(钥 + "\|" + "page=N&ts=T&enc=" + enc)` | `Fatdog_abyss`（so 里，异或藏） | 普通 MD5 |

- 签名原文：`Fatdog_abyss|page=<N>&ts=<T>&enc=<enc>`——注意前缀是**钥 + 竖线**，格式与钥都得还原。
- 诱饵钥 `Fatdog_deep`（so 的诱饵数组 + `DepthKit` 类），签了 403。
- 反调试：三路信号（TracerPid / ptrace 失败 / maps 含 frida\|gdb\|lldb\|gum-js）各记 1 分，**≥2 才判定**（评分制防误杀）；判定成立 → 用诱饵钥签名。

**路线一 · 静态复刻（Python，完整可跑）**：
```python
import requests, time, hashlib

# --- 纯标准库 AES-128-ECB（第一层；与 server.py 的 _aes_* 同一份实现） ---
SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
RCON = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54]

def gm(a, b):                      # GF(2^8) 乘法
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80; a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return p & 0xFF

def expand(key):                   # 密钥扩展 → 11 组轮密钥
    w = list(key)
    for i in range(4, 44):
        t = w[(i-1)*4:(i-1)*4+4]
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[i//4 - 1]
        w += [w[(i-4)*4]^t[0], w[(i-4)*4+1]^t[1], w[(i-4)*4+2]^t[2], w[(i-4)*4+3]^t[3]]
    return w

def encrypt_block(rk, blk):
    s = list(blk)
    def add(r):
        for i in range(16): s[i] ^= rk[r*16+i]
    def sb():
        for i in range(16): s[i] = SBOX[s[i]]
    def sh():
        t = s[:]
        for r in range(4):
            for c in range(4): s[r+4*c] = t[r+4*((c+r)%4)]
    def mx():
        for c in range(4):
            i0 = c*4; a0,a1,a2,a3 = s[i0],s[i0+1],s[i0+2],s[i0+3]
            s[i0]   = gm(2,a0)^gm(3,a1)^a2^a3
            s[i0+1] = a0^gm(2,a1)^gm(3,a2)^a3
            s[i0+2] = a0^a1^gm(2,a2)^gm(3,a3)
            s[i0+3] = gm(3,a0)^a1^a2^gm(2,a3)
    add(0)
    for r in range(1, 10): sb(); sh(); mx(); add(r)
    sb(); sh(); add(10)
    return bytes(s)

KEY  = b"Fatdog_abyss"             # 真钥（混淆 JS + so 两处还原）
AKEY = (KEY + b"\x00" * 16)[:16]   # AES-128 钥 = 标记补零到 16 字节

def aes_ecb(data):
    rk = expand(AKEY); out = bytearray()
    for i in range(0, len(data), 16): out += encrypt_block(rk, data[i:i+16])
    return bytes(out)

def pkcs7(b):                      # PKCS#7 补齐
    n = 16 - len(b) % 16
    return b + bytes([n]) * n

BASE = "https://10.0.2.2:8443"
s = requests.Session(); s.verify = False       # 自签证书
total = 0
for page in range(1, 101):
    ts  = int(time.time())
    enc = aes_ecb(pkcs7(f"page={page}&ts={ts}".encode())).hex()                  # 第一层
    sign = hashlib.md5(KEY + f"|page={page}&ts={ts}&enc={enc}".encode()).hexdigest()  # 第二层
    r = s.post(f"{BASE}/api/kl45", data={"page": page, "ts": ts, "enc": enc, "sign": sign})
    total += sum(r.json()["nums"])
print("sum =", total)             # 50517
```

**JS 逆向详解（本关第一层）**：
1. 页面 `assets/h5/hybrid_kl45.html` 不加密，直接抠 `<script>`（约 **22.5KB**，ob 混淆：`fd` 前缀十六进制标识符 + 字符串数组 + rc4 编码 + 控制流平坦化 + 数字表达式化）→ 套用「JS 逆向通用流程」反混淆（`de4js` 一键 / `js-beautify` 后手工替换 `fd0x…(0x…)` 取串调用）。
2. 还原后得到：
```javascript
var AES_KEY = "Fatdog_abyss";                 // 第一层钥（真源里可见，混淆后藏进字符串数组）
function fdPack(page, ts) {                    // 挂在 window.fdPack
  var pt = "page=" + page + "&ts=" + ts;
  return toHex(aesEcbEncrypt(padZero16(AES_KEY), pkcs7(strToBytes(pt))));   // AES-128-ECB + PKCS#7 → hex
}
```
3. 结论：**第一层钥 = `Fatdog_abyss`（补零到 16 字节），算法 = AES-128-ECB，明文 = `page=<N>&ts=<T>`，输出 hex**（16 字节 → 1 块 → 32 hex；本例明文 22 字节 → 补齐 32 字节 → 2 块 → 64 hex）。
4. 对拍：本关 `enc(1,1787013761) = fde4cf8e74b7234e9b74a8518d68f45104e418d80767db6e8276cdc6dc4a3c21`（可用它验证你的 AES 实现对不对）。
5. 动态：页面函数挂在 `window.fdPack`，`evaluateJavascript("window.fdPack(1,1700000000)")` 直接拿密文；或 hook `HybridCore.nativeFullSign` 看 native 入参（就是 enc）。

**路线二 · Frida 动态**：
```javascript
Java.perform(function () {
    var HC = Java.use("com.fatdog.reverse.HybridCore");
    console.log("guard = " + HC.nativeStatus());          // 反调试自检（只读）
    HC.nativeFullSign.implementation = function (page, ts, enc) {
        var r = this.nativeFullSign(page, ts, enc);
        console.log("page=" + page + " ts=" + ts + " enc=" + enc + "\n -> sign=" + r);
        return r;
    };
});
```

**反调试绕过要点**：评分制（≥2 分才判定），正常设备最多命中 1 项，不会误杀；挂调试器时 TracerPid 与 ptrace 同时中招。省事做法是静态复刻两层；`nativeStatus()` 只做只读展示，不参与判胜、也不吐钥。

**答案**：100 页共 1000 个数求和 = **50517**。flag `FLAG_19_KL45{abyssal_union}`。真钥 `Fatdog_abyss`；诱饵 `Fatdog_deep`（403）。

**坑位**：
- AES 是**分组密码**：明文必须 PKCS#7 补齐到 16 字节整倍数；密钥须 **16 字节**（`Fatdog_abyss` 只有 12 字节，须补 4 个零字节）。
- 第二层签名原文前缀是**钥 + 竖线**（`Fatdog_abyss|page=..`），漏前缀或漏竖线都验不过。
- 密文是 **hex**；ECB 无 IV——相同明文得到相同密文，这也是识别「ECB 模式」的线索。
- SEED_KL45=20280905，启动日志打印 `KL45=50517`。


| 关卡 | Flag |
|------|------|
| KL41 | `FLAG_19_KL41{shallow_shell_found}` |
| KL42 | `FLAG_19_KL42{sand_hidden_shell}` |
| KL43 | `FLAG_19_KL43{wind_on_the_bridge}` |
| KL44 | `FLAG_19_KL44{undertow_surging}` |
| KL45 | `FLAG_19_KL45{abyssal_union}` |


> 备注：L43-L45 现版源码庆祝串均为 `FLAG_18_L48{mirror_tells_true}`（L48 为历史编号残留、三关复制未改），上表按关卡语义区分；L47 以当前 App 庆祝串 `FLAG_18_L47{guard_matrix_crc_aes}` 为准。关卡 9 有两个变体串（`single_gate_not_enough` 是只过一重门时的诱饵/半程提示）。
