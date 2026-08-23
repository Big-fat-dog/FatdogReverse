# FatdogReverse —— 按教程系列打造的 Android 逆向闯关靶场

一个专为《pyteacher 逆向教程》系列配套的练习 App。第一季覆盖四块：

- **关卡 1-6** —— 教程 18《APK 结构与 jadx 静态分析入门》：纯静态分析，从 jadx 搜字符串到资源、Manifest、哈希校验；
- **关卡 7-9** —— 教程 19《逆向 Java 基础与 smali》：smali 修改挑战，难度递增；
- **关卡 10-14** —— 教程 20《Frida Hook 实战（Java 层）》：对参数做加/解密/哈希后验证结果的实战，难度递增；
- **关卡 15-19** —— 网络取数系列（数据只在本地服务端）：HMAC / RC4 / 国密 / RSA+DES / AES+HMAC（L19 加密类经 R8 混淆）；
- **关卡 20** —— 教程 19 的进阶：**万恶广告劫**（改 smali 关弹窗）——进去只有一个"点此领取 1 亿大礼包"按钮，点了就弹连环牛皮癣广告：× 前 5 秒不显示、显示了也瞬移、还弹嘲讽 Toast，正常操作永远关不掉；正解是 apktool 把广告开关关掉。
- **关卡 21-26** —— 第二季 SSL 抓包系列（HTTPS + 自定义 TrustManager / OkHttp CertificatePinner / WebView 自签证书白屏 / 反 Hook 检测 + 内存换 pin / JNI native 校验 / 双向 TLS mTLS 客户端证书）。
- **关卡 27** —— **万法归宗**：HTTPS 双闸门（TrustManager+CertificatePinner）+ 复合签名（AES 参数加密 + HMAC，响应加密，加密包 R8 混淆），抓到明文≠采集成功，复刻整条签名链才算通关。
- **关卡 28 起** —— 第三季 Native 试炼系列（教程 22《Frida Hook 实战 Native 层》配套）：每关独立 so 防剧透，密钥标记弃用 fatdemo 改用 `Fatdog_<情绪词>`（情绪词用尽换动词）；大厅新增「Native 试炼」分区。

> 所有网络关（15-22、24-25）采用**分页加载**：顶部输入/翻页条（页码窗口、上一页/下一页、跳转到指定页），下方两排数字（10 个/页）。点页码窗口会自动左移 3 格——1 2 3 消失、多出后面 3 个页码，像手掌翻页一样。关卡 23 例外：它加载的是 HTTPS H5 页，没有分页——页面白屏本身就是题面。

APK 结构刻意做得和真实 App 一致：图标（5 种密度）、XML 布局、strings 资源、resources.arsc、单个 classes.dex（**R8 混淆打包**，关卡 19 的 `o` 包与关卡 27 的 `p` 包被改名；无 classes2/classes3）、assets/config.json、双架构 so（关卡 25 的 JNI 校验在此）、META-INF 签名三件套。

> **关于类名**：关卡 1-11 的类名是"表达功能含义"的名字（如 `VipSalonActivity`），关卡 12 开始**类名刻意变"难读"**（如 `b1Activity`、`k4Activity`、`z9Activity`、`s5Activity`），一个关卡的内容会**分散在多个类**里，还会混入**没人调用的诱饵工具类**（AesKit、Md5Tools、KeyFactory、TokenGen、DigestBox…）。"关卡 N 对应哪些类"必须靠交叉引用自己找，这本身就是逆向的一部分。

> **关卡 19 小提示**：加密逻辑在 `com.fatdog.reverse.o` 包，构建时用 R8 混淆（keep 规则只放行该包重命名），算法名/路径/密钥均为异或加密字符串——jadx 里搜 `AES`、`/api/…` 都搜不到。别慌，找 `v9Activity` 的调用链即可顺藤摸瓜。

## 关卡总览

| 关卡 | 名称 | 考点 | 对应教程 |
|---|---|---|---|
| 1 | 明文藏宝 | flag 以明文写死在 dex 里，jadx 全文搜索 | 18 篇：字符串是静态分析的第一线索 |
| 2 | Base64 马甲 | 以 `=` 结尾的编码串，先想到 Base64 | 08 篇：Base64 不是加密 |
| 3 | 拼图游戏 | 字符串被拆散 + 字符异或运算 | 18 篇：拼接与运算混淆 |
| 4 | MD5 验门 | 32 位哈希常量、输入与哈希比对 | 09 篇：MD5 摘要与在线查表 |
| 5 | 资源藏宝 | flag 藏在 assets/config.json 的字段里 | 18 篇：APK 结构中的资源 |
| 6 | 隐藏入口 | Manifest 里的 exported Activity，无 UI 入口 | 18 篇：四大组件与 Manifest |
| 7 | VIP 检测（smali） | 修改 smali 去掉 isVip 检测 | 19 篇：smali 寄存器/指令/跳转 |
| 8 | 激活码（smali） | smali 里的 fill-array-data 密文，改 checkKey 或还原激活码 | 19 篇：smali 字节数组与 fill-array-data |
| 9 | 多重资格（smali） | 多重检查 + 诱饵 flag，需完整理解 smali 逻辑 | 19 篇：smali 短路与逻辑链 |
| 10 | SHA-256 验门（Frida） | 输入口令，SHA-256 比对内置哈希 | 20 篇：Hook MessageDigest / 篡改 verify |
| 11 | HMAC 验签（Frida） | 输入口令，HMAC-SHA256 比对 | 20 篇：Hook Mac.doFinal |
| 12 | AES 密码库（Frida） | 输入密码，AES-CBC 解密密文比对（密钥/IV/密文分散在工具类） | 20 篇：Hook Cipher.doFinal + 类分散 |
| 13 | 双重校验（Frida） | 账号 MD5 + 令牌 AES，双参数，逻辑跨两个工具类 | 20 篇：同时 Hook 多算法 |
| 14 | 三层链路（Frida） | license 过三层变换（2×AES + 异或）+ deviceId MD5，密钥分散+大量诱饵 | 20 篇：链式 Hook + 识别诱饵 |
| 15 | 千数求和 | 1000 个数=100 页×10 个，请求带 HMAC 签名，数字只在本地服务端 | 20/07 篇：请求签名复刻 + 发包取数 |
| 16 | 流密码暗河 | 请求参数整段加密（RC4）+ MD5 签名，响应体加密，60 页×8 个 | 20/13 篇：RC4 复刻 + 双向加解密取数 |
| 17 | 玄门遁甲 | POST 表单 enc/sig/dog/ts 校验，请求参数加密（国密 SM4）+ 摘要（SM3），100 页×10 个 | 20+国密：SM4/SM3 复刻 + 表单取数 |
| 18 | 乾坤密钥 | RSA 公钥加密请求参数 + DES 解密响应，密钥一半服务端下发、一半藏在 App | 20+RSA/DES：混合密钥复刻 + 发包取数 |
| 19 | 雾里看花 | 请求参数加密（AES）+ HMAC 签名，响应体加密；**加密包被真 R8 混淆、字符串加密** | 20+R8：先认混淆再复刻 |
| 20 | 万恶广告劫（smali） | 连环牛皮癣广告：switch(step) 状态机弹 8 条广告、× 瞬移 + 嘲讽 Toast、正常关不掉；正解 apktool 把 AdBox.a 开关改 0 | 19 篇：smali 字段/跳转/switch 状态机 |
| 21 | 踏云寻踪 | HTTPS + 自定义信任（内置自签 CA），请求带 HMAC 签名，100 页×10 个 | 21 篇：TrustManager / 抓包对抗入门 |
| 22 | 双锁封疆 | HTTPS + 证书锁定（SPKI 焊死）+ 自定义信任，双闸门 | 21 篇：OkHttp pinning / 双闸门绕过 |
| 23 | 白屏迷雾 | WebView 加载 HTTPS H5，自签证书错误被 handler.cancel() 白屏；Hook onReceivedSslError → proceed() 拿 flag | 21 篇：WebView 证书错误处理 |
| 24 | 换票迷局 | HTTPS + pin 校验带反 Hook 守卫（Hook 校验就异常），正解 Frida 内存换 pin；100 页×10 个求和 | 21 篇：反 Hook 检测 / 内存换值 |
| 25 | 灵台证真 | HTTPS + JNI native 校验（verifyServer 门禁 + nativeSign 签名都在 libnative.so），Java Hook 无效 | 22 篇预告：native 逆向与 JNI |
| 26 | 双符合璧 | 双向 TLS（mTLS）：服务端握手层强制验证客户端证书；APK 内置 mt_client.p12，密码拆两半藏在异或数组里 | 21 篇进阶：客户端证书提取、PKCS12、mTLS 复刻 |
| 27 | 万法归宗 | HTTPS 双闸门 + 复合签名：AES 参数加密 + HMAC 签名 + 响应加密，加密包 R8 混淆；抓包→复刻全闭环 | 21+20 篇合卷：绕 pinning 抓密文 → 解混淆还原签名链 → 100 页取数 |
| 28 | 缄默之钥 | 密钥 ^0x5C 藏进 libl28.so 的 .rodata，strings 只有诱饵 Fatdog_silent；IDA 读解码循环或运行时内存搜明文，HMAC 复刻取数 | 22 篇：字符串加密只骗静态，内存必有明文 |
| 29 | 隐姓埋名 | 真身经 JNI_OnLoad 动态注册（无名 static 函数）；导出表两个假 nativeSign 是坑，按名 Hook 不触发或拿错值 | 22 篇：RegisterNatives 抓映射 + spawn 抢时机 |
| 30 | 无名剑冢 | 四个同形签名函数经函数指针表派发，只有一个是真身；密钥 UTF-16 藏匿（strings 盲区），服务器当裁判验真 | 22 篇：间接调用分析 + 候选对拍验真 |
| 31 | 两界穿针 | 密钥跨层拼装（Java 改名 q 包持 Fatdog_ + so 持 lonely，native 回调取件）；RC4 参数加密 + HMAC；每页连发 4 个同形包辨真假 | 22 篇：JNIEnv 回调分析 + 响应内容甄别 |
| 32 | 心魔哨兵 | 四路反检测哨兵（maps/端口/线程名/TracerPid）随 so 启动轮询；挂 Frida 即静默投毒一字节、签名全错，App 仅弹一次警告 | 22 篇 §14：反调试指纹与洗地对抗 |
| 33 | 金刚不坏 | 可执行段 CRC32 自校验（基线建于 JNI_OnLoad）+ assertGuard 记账守卫；任何 inline hook 都被抓，三解全开（抢跑建基线/hook 校验器/改基线变量） | 22 篇：自完整性校验与时机对抗 |
| 34 | 万法归墟 | 综合卷：动态注册 + 无名 Feistel8 参数加密 + HMAC + 四路哨兵 + CRC + 记账 + 响应 RC4（密钥派生）；官方路线 Frida/patch so/unidbg 三选一 | 22 篇合卷：三季所学一关收束 |
| 35 | 双匣暗渡 | 手写 3DES+SM4 藏进满屏诱饵函数，认算法靠 S 盒魔数（14,4,13,1… / d6 90 e9 fe…）；双密文参数 + 动态 ts；每页三连包辨真假 | 13+15 篇：密码学指纹识别 |
| 36 | 查表识君 | 手写 AES-128 沉底派发（S 盒 637c777b…）；钥匙藏在 .rodata 的 Base64 串里，解码即得——Base64 不是加密 | 02+12 篇：编码伪装与 AES 指纹 |
| KL1 | 山门 | unidbg 最小骨架：load→调导出函数 kl_gate（xorshift32 七轮） | 25 篇配套 |
| KL2 | 引雷桩 | JNI_OnLoad 动态注册 + 同名诱饵导出，必须先触发 OnLoad | 25 篇：RegisterNatives 实战 |
| KL3 | 渡鸦桥 | native 回调 Java halfA() 取前半密钥，unidbg 补 AbstractJni 桩 | 25 篇：CallStaticObjectMethod 拦截 |
| KL5 | 登顶 | 综合卷：动态注册 + Java 回调 + XOR 解密；nativeClimb 回调 summitKey() 取 Fatdog_ 与 so 内 summit 拼合解密 flag | 全线：unidbg 综合实战 | 读 /proc/self/maps 搜模拟器特征 + TracerPid 检测；环境干净返回通行令牌，否则冰面碎裂 | 25 篇：IOResolver 喂假文件过反模拟 | 手写 SHA-256 变体：骨架/K 表没动、初始 IV 整组换血，摘要再叠 RC4——hashlib 永远对不上；认骨架、找改动点 | 09 篇进阶：从指纹到改点 |

每关的**解题思路分级提示**见下方折叠块；完整题解（含 Python 复刻代码与 Frida 脚本）在 `SOLUTIONS.md`（建议先自己练）。

## 通用流程

**静态分析（1-6 关）**：`jadx` 打开 APK → 搜 `FLAG_18` → 逐关按提示走。

**smali 修改（7-9、20 关）**：需要 apktool 解包/回编译 + zipalign/apksigner 重签名：

```
apktool d FatdogReverse.apk -o out          # 单 classes.dex → out/smali/com/fatdog/reverse/...
# 关卡 20：打开 out/smali/com/fatdog/reverse/AdBox.smali，
#   .field public static a:I = 0x1  ← 把 0x1 改成 0x0（广告开关）
#   （或把 showAd 门口 sget a:I + if-nez 反转为 if-eqz）
# 编辑对应 .smali
apktool b out -o rebuilt.apk
zipalign -f 4 rebuilt.apk aligned.apk
apksigner sign --ks build/debug.keystore --ks-key-alias androiddebugkey \
        --ks-pass pass:android --key-pass pass:android --out FatdogReverse-patched.apk aligned.apk
adb install -r FatdogReverse-patched.apk
```

> 关卡 20 的广告是 Java 结构化的 switch 状态机（jadx 展开成巨型 switch + 一堆神秘数字），smali 里反而是清晰的 `packed-switch` 表 + 一眼可见的开关 `sget AdBox->a:I`——这关教的是"读 smali 比读反编译 Java 还顺"。

**个人主页（修仙境界）**：大厅最底部有"个人主页"按钮。每通过一关（在关卡里触发 flag）都会自动打点记录；主页根据**通关数量**定境界——炼气~元婴每 5 关一层；**化神起每 10 关为一个大境界，第 10 层为"圆满"**：

| 通关数 | 境界 |
|---|---|
| 0 | 凡人 |
| 1-5 | 炼气 一层~五层 |
| 6-10 | 筑基 一层~五层 |
| 11-15 | 金丹 一层~五层 |
| 16-20 | 元婴 一层~五层 |
| 21-30 | 化神 一层~九层、圆满 |
| 31-40 | 洞虚 一层~九层、圆满 |
| 41-50 | 归墟 一层~九层、圆满 |
| 51-60 | 无量 一层~九层、圆满 |
| 61+ | **独断万古**（终点，之后无论通关多少次都是它） |

主页还显示当前境界的描述、进度条（█/░）和"再通 X 关迈入下一境界"的提示。**化神起境界徽章带柔和呼吸光晕**（低透明度慢节奏脉动，不刺眼）；终点"独断万古"独占深空鎏金渐变徽章与金色光晕。

主页底部有四个分类页签：基本情况 / 太古禁地 / 神念自察 / 天地秘境。天地秘境为高阶关卡的故事阅读器（通关对应关卡解锁），当前为占位状态。

---

**Frida 动态 Hook（10-15 关）**：需要真机/模拟器 + frida-server（教程 20 有完整安装流程）。通用观察脚本长这样：

```javascript
// hook_crypto.js —— 通用加密原语 Hook：不管业务怎么藏，明文都要经过这里
Java.perform(function () {
    function bytesToHex(b) { var s = ''; for (var i = 0; i < b.length; i++) { var x = b[i] & 0xff; s += ('0' + x.toString(16)).slice(-2); } return s; }
    var MD = Java.use('java.security.MessageDigest');
    MD.update.overload('[B').implementation = function (d) { console.log('[digest] 输入:', bytesToHex(d)); return this.update(d); };
    MD.digest.overload().implementation = function () { var r = this.digest(); console.log('[digest] 输出:', bytesToHex(r)); return r; };
    var Mac = Java.use('javax.crypto.Mac');
    Mac.doFinal.overload('[B').implementation = function (d) { console.log('[mac] 输入:', bytesToHex(d)); var r = this.doFinal(d); console.log('[mac] 输出:', bytesToHex(r)); return r; };
    var C = Java.use('javax.crypto.Cipher');
    C.doFinal.overload('[B').implementation = function (d) { console.log('[cipher] 输入:', bytesToHex(d)); var r = this.doFinal(d); console.log('[cipher] 输出:', bytesToHex(r)); return r; };
});
```

**网络关卡（15-22、24-27 关统一分页加载 + 23 关 WebView H5 页）**：先启动本地服务端（FastAPI），再分析/复刻签名取数：

```
# 终端 1：启动模拟服务端（数字只在这里，APK 里没有）
pip install fastapi uvicorn python-multipart pycryptodome   # 首次需要
python server.py          # HTTP :8787（15-20） + HTTPS :8443（21-25，自签 CA） + HTTPS :8444（26，mTLS 强制客户端证书）

# 模拟器：App 自动请求 http://10.0.2.2:8787（NetHost 识别到模拟器，默认即可）
# 真机：  adb reverse tcp:8787 tcp:8787（地址自动切换，无需改 config.json）
#        HTTPS 关（21-25）同理：adb reverse tcp:8443 tcp:8443（地址自动切换）
#        L26 的 mTLS 端口：adb reverse tcp:8444 tcp:8444
#        L23 的 H5 页只讲 HTTPS：https://…:8443/h5/v23（HTTP 访问直接 403）
```

地址自动切换：`config.json` 的 `api_base_url` 默认 `"AUTO"`——模拟器自动走 `10.0.2.2`、真机自动走 `127.0.0.1`（识别不出模拟器特征时按真机处理）；也可手动填 `http://局域网IP:8787` 覆盖，手机与电脑同一网络即可免 USB。

各网络关要点：L15 HMAC 明文参数；L16 请求整段加密+MD5 签名、响应加密（RC4）；L17 表单 enc/sig/dog（国密 SM4+SM3，纯 Python 实现）；L18 RSA 加密请求参数 + DES 解密响应（密钥一半服务端下发）；L19 AES 加密参数 + HMAC 签名、响应加密（加密包 R8 混淆 + 字符串加密）；L21/L22 走 HTTPS + 自签 CA（TrustManager / CertificatePinner 双闸门）；L23 走 WebView 加载 https://…:8443/h5/v23（主机自动选择；仅 HTTPS，HTTP 直接 403）：自签证书不被信任 → App 在 onReceivedSslError 里 handler.cancel() → 白屏，Hook 放行后页面出现、自动通关。L24 走 HTTPS + 内置 CA + HostnameVerifier pin 校验（pin 无明文，XOR 数组藏在 Z24Core），校验链带反 Hook 守卫——Hook 校验函数直接放行会触发"完整性校验失败"，正解是 Hook Z24Core.realPin 内存换 pin（换票）。L25 走 HTTPS + JNI：发请求前调 Nx.verifyServer（native 主机白名单），签名 Nx.nativeSign 在 libnative.so 里算 HMAC-SHA256——密钥不在 Java（strings libnative.so 可见 fatdemo_jni_2026），Hook Mac/MessageDigest 无效，正路是静态逆向 so 复刻或 Frida 原生层调用。**L26 走双向 TLS（mTLS）**：`https://…:8444/api/mtls`，服务端握手层强制验证客户端证书（只信内置 CA 签发的）；App 从 `assets/mt_client.p12` 加载客户端证书+私钥（密码 `fatdemo_mt26` 拆在 Zt/Mc 的异或数组里），没这张证书连握手都过不去——先抠证书解密码，再带 client 证书复刻取数（加和 50814）。**L27 万法归宗**走 HTTPS :8443 的 `POST /api/l27` + 复合签名：`enc=AES(page=N&ts=T)`、`sign=HMAC(enc)`、响应 `{"d"}` 再过一层 AES；加密核心在 `com.fatdog.reverse.p` 包（构建时被 R8 改名 + 算法名/路径/密钥全是异或串），三把密钥各拆两半跨类拼装。抓包得先放倒 TrustManager + CertificatePinner 两道闸——而且抓到的也只是 enc 密文：从 c27Activity 的调用链摸进混淆包还原签名链，才能复刻取数（加和 50623）。L28 走 native 字符串加密：密钥 ^0x5C 藏 libl28.so（strings 只见诱饵 Fatdog_silent），IDA 还原 Fatdog_unhappy 或 Frida 运行时搜明文，加和 49750；L29 走动态注册：导出表两个假 nativeSign 全是坑，真身无名靠 spawn+hook libart RegisterNatives 抓映射，密钥 Fatdog_angry 异或藏 .data，加和 50208。L30 走无名派发：四候选同形函数挂函数指针表、UTF-16 密钥躲过默认 strings（`strings -el` 可破），真钥 Fatdog_gloomy，加和 51127。L31 走跨层拼装：Fatdog_ 藏在 R8 改名的 q 包、lonely 是 so 里的 UTF-16 数组，native 回调 Java 取件；每页连发 1 真 + 3 干扰同形包（错位/废签/噪声），假包要么 403 要么 nums 为空，加和 50768。L32 走反检测：四路哨兵扫 maps/探端口/查线程名/盯 TracerPid，挂着 Frida 就静默投毒一字节（签名全错），App 只弹一次警告；静态复刻党全程免疫，动态党得先让哨兵闭嘴，加和 51745。L33 走自完整性校验：可执行段 CRC 基线 + 记账守卫，纯观察钩子也会被抓，三解全开（JNI_OnLoad 抢跑/hook 校验器/改基线），加和 49502。L34 万法归墟收官：Feistel8 参数加密让纯猜必死、响应再裹一层 RC4（密钥派生）、守卫全家桶伺候——Frida/patch so/unidbg 三路皆通，加和 49932。L35 手写 3DES+SM4 埋进诱饵堆里，靠 S 盒魔数认阵（strings -el 先拿 Fatdog_sneak 再派生双钥）；双密文参数 + 动态 ts + 三连包辨真假，加和 51217。L36 手写 AES-128 沉底，钥匙是 so 里那串 == 结尾的 Base64——解开就是 16 字节真钥，Python 复刻取数加和 49495。L37 收官卷：SHA-256 变体（IV 整组换血）叠 RC4，hashlib 永远对不上；strings -el 拿标记后按服务端同款逻辑复刻变体即可，加和 51242。天地秘境 KL1-KL5 已全部落地：KL1 xorshift32 直接调、KL2 动态注册+诱饵、KL3 跨层回调取钥、KL4 反模拟检测（IOResolver 喂假文件过检）——全部纯本地提交模式，入口通关 37 关或密令 Fatdog。提交答案分别为 -303563272 / -2146415444 / Fatdog_raven / Fatdog_glacier_unlocked。

## 环境准备

构建只需要三样东西，**不需要 Android Studio / Gradle**：

1. **JDK 17+** —— 任意 JDK 17+ 均可（官方 OpenJDK、IntelliJ/PyCharm 自带 JBR 都行）。命令里把 `<你的 JDK 根目录>` 换成实际路径（例如 `D:\JAVA`）。
2. **Android SDK 的 build-tools 与 platforms**：
   - 下载 [commandline-tools](https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip)，解压到 SDK 根目录（目录结构：`<SDK 根目录>\cmdline-tools\latest\bin`，例如 `D:\Andorid\SDK`）。
   - 设置环境变量 `ANDROID_SDK_ROOT` 指向 SDK 根目录（`build_apk.py` 也会自动探测 `%LOCALAPPDATA%\Android\Sdk` 等常见路径）。
   - 运行：
     ```
     set JAVA_HOME=<你的 JDK 根目录>
     <SDK 根目录>\cmdline-tools\latest\bin\sdkmanager.bat "platform-tools" "platforms;android-34" "build-tools;34.0.0"
     ```
3. **NDK（关卡 25 必需，其余关可选）**：
   ```
   <SDK 根目录>\cmdline-tools\latest\bin\sdkmanager.bat "ndk;26.1.10909125"
   ```
   不装 NDK 也能构建出 APK，但会缺 `lib/*.so`——关卡 25 的 native 校验（verifyServer/nativeSign）就在里面，缺了进不去。
4. **关卡 7-9 需要 apktool**；**关卡 10-16 需要 Frida**（`pip install frida-tools` + 设备端 frida-server，版本必须一致）；**网络关 15-22、24-26 需要 Python 标准库（15/16）+ pycryptodome（17/18/19）+ cryptography（26 解 p12），关卡 23 无需额外依赖（curl -k 或 Frida）；真机玩 15-26 网络关需 `adb reverse`（或用局域网 IP 覆盖）**；服务端需要 `pip install fastapi uvicorn python-multipart pycryptodome`。

## 构建与安装

```
cd /d <你的项目目录>
python build_apk.py

adb install -r FatdogReverse.apk
```

构建产物 `FatdogReverse.apk` 就是你的靶子（桌面图标为胖狗），启动后显示"胖狗逆向靶场"：用 jadx 打开它，开始闯关。

## 项目结构

```
FatdogReverse/
├── build_apk.py            # 一键构建（aapt2 + javac + R8 混淆打包 + 可选 smali 汇编 classes3 + 可选 ndk-build + apksigner）
├── r8.pro                  # R8 keep 规则：只放行 com.fatdog.reverse.o 包改名，其余全部保留原名可读
├── gen_certs.py            # 关卡 21-25 的 HTTPS 证书生成（自签 CA + 服务器证书）
├── certs/                  # 生成的证书（ca.crt / server.crt / server.key，不入 APK）
├── libs/                   # OkHttp/Okio/Kotlin 依赖 jar + 注解 jar
├── server.py               # 关卡 15-25 本地模拟服务端（FastAPI，数字/页面只在这里）
├── FatdogReverse.apk             # 构建产物
├── README.md               # 本文件
├── SOLUTIONS.md            # 完整题解（先看别看！）
├── PLANNED.md              # 开发规划与状态（15-25 已全部落地）
├── tools/                  # smali/baksmali 等 jar
└── app/
    ├── AndroidManifest.xml # 关卡 6 的关键线索藏在这里
    ├── assets/config.json  # 关卡 5 的宝藏；关卡 15 的 API 地址也在里面
    ├── jni/                # libnative.so 源码（关卡 25 的 native 门禁 + HMAC 签名在此）
    ├── res/
    │   ├── layout/activity_main.xml   # 大厅布局（14 个按钮，没有关卡 6）
    │   ├── values/strings.xml         # 字符串资源
    │   └── mipmap-*/                  # 5 种密度的 launcher 图标
    └── src/com/fatdog/reverse/
        ├── MainActivity.java          # 关卡大厅
        ├── TokenVaultActivity.java    # 关卡 1
        ├── NoteKeeperActivity.java    # 关卡 2
        ├── PuzzleBoxActivity.java     # 关卡 3
        ├── GateKeeperActivity.java    # 关卡 4（classes.dex）
        ├── ConfigCenterActivity.java  # 关卡 5（classes.dex）
        ├── VipSalonActivity.java      # 关卡 7（smali，classes.dex）
        ├── ActivationRoomActivity.java# 关卡 8（smali，classes.dex）
        ├── ProWorkshopActivity.java   # 关卡 9（smali，classes.dex）
        ├── HashCheckActivity.java     # 关卡 10（Frida）
        ├── MsgAuthActivity.java       # 关卡 11（Frida）
        ├── b1Activity.java + SBox.java# 关卡 12（Frida，内容分散；Md5Wrap/MiscCrypt 是诱饵）
        ├── k4Activity.java + SignUtil.java + KBox.java  # 关卡 13（Frida；HashFactory 是诱饵）
        ├── z9Activity.java + XBox.java + Mux.java       # 关卡 14（Frida；AesKit/Md5Tools/KeyFactory 是诱饵）
        ├── s5Activity.java + Sg.java + Kx.java          # 关卡 15（网络；TokenGen/DigestBox 诱饵）
        ├── t6Activity.java + C16.java + Rc4Core.java + Jk.java          # 关卡 16（网络；B64Kit/TokenGen/DigestBox 诱饵）
        ├── u7Activity.java + Fl.java + Kt.java + Sm4Core.java + Sm3Core.java  # 关卡 17（网络/国密；NetPacker 诱饵）
        ├── v8Activity.java + Rs.java + Pk.java                            # 关卡 18（网络/RSA+DES；RsaKit 诱饵）
        ├── v9Activity.java + o/*                                         # 关卡 19（网络/AES+HMAC，加密包 R8 混淆）
        ├── a20Activity.java + AdBox.java + Sx.java + PhantomAd.java   # 关卡 20（smali/连环广告；PhantomAd 假开关诱饵）
        ├── w1Activity.java + Tm.java + Km.java                            # 关卡 21（HTTPS/自定义信任；CertBox 诱饵）
        ├── x2Activity.java + Pn.java + Kp.java                            # 关卡 22（HTTPS/证书锁定；Pim 诱饵）
        ├── NetHost.java              # 全局环境探测：模拟器 10.0.2.2 / 真机 127.0.0.1（默认真机）
        ├── y3Activity.java + Hq.java + WvKit.java        # 关卡 23（WebView/自签证书白屏；WvKit 诱饵）
        ├── z24Activity.java + Aw.java + Tk.java + Z24Core.java   # 关卡 24（HTTPS/pin + 反 Hook 守卫；Gp 诱饵）
        ├── a25Activity.java + Nx.java + By.java + libnative.so   # 关卡 25（JNI native 校验；Rj 诱饵）
        ├── b26Activity.java + Vd.java + Mc.java + Zt.java        # 关卡 26（mTLS/双向 TLS + PKCS12；MtlsKit 诱饵）
        ├── c27Activity.java                                      # 关卡 27（万法归宗；入口保持可读，调用链通向 p 包）
        ├── p/Wire.java + Gate.java + Cpt.java + Mk.java + Tail.java   # 关卡 27 加密/网络核心（R8 改名；Gh 是包内诱饵）
        ├── EndKit.java                                           # 关卡 27 根包诱饵（假密钥假端点）
        ├── ProfileActivity.java    # 个人主页：修仙境界（顶部传送带分类：基本情况/太古禁地/神念自察）
        ├── PassLog.java            # 通关进度记录（各关触发 flag 时自动打点）
        └── RewardActivity.java     # 关卡 6（大厅里没有入口）
    # APK 只有单个 classes.dex（R8 打包全部关卡，无 classes2/classes3）
```

## 分级提示（按需展开）

<details>
<summary>关卡 1 · 轻度提示</summary>

jadx 全文搜索 `FLAG_18`。

</details>

<details>
<summary>关卡 2 · 轻度提示</summary>

那串以 `=` 结尾的字符串，用 Python `base64.b64decode(...)` 解码。

</details>

<details>
<summary>关卡 3 · 轻度提示</summary>

jadx 里是一堆 `(char) ('y' ^ 1)` 表达式。异或的逆运算就是它自己。提示：`'y' ^ 1 = 'x'`。

</details>

<details>
<summary>关卡 4 · 轻度提示</summary>

代码里有一个 32 位十六进制串。到 cmd5.com 这类在线查表站查一下；查不到就写几行 Python 爆破纯数字密码。

</details>

<details>
<summary>关卡 5 · 重度提示</summary>

APK 就是个 zip。改后缀解压，打开 `assets/config.json`，找一个不太对劲的字段。

</details>

<details>
<summary>关卡 6 · 重度提示</summary>

看 `AndroidManifest.xml` 里声明的所有 Activity，找一个大厅没引用、但 `exported="true"` 的：

```
adb shell am start -n com.fatdog.reverse/.RewardActivity
```

</details>

<details>
<summary>关卡 7 · 轻度提示</summary>

apktool 解包，打开 `smali/.../VipSalonActivity.smali`，找到 `isVip()Z`：`const/4 v0, 0x0` 后面 `return v0` 就是"恒不是 VIP"。把 `0x0` 改成 `0x1`，回编译重签名重装。或者把按钮回调里的 `if-eqz` 反过来。

</details>

<details>
<summary>关卡 8 · 中度提示</summary>

期望的激活码在 smali 里是一段 `.array-data` 字节（`buildKey()` 里，`fill-array-data` 后面）。把每个字节 `^ 0x2A` 还原成字符串，直接输入即可；或者更暴力一点——把 `checkKey()` 的方法体整体改成 `const/4 v0, 0x1` + `return v0`。

</details>

<details>
<summary>关卡 9 · 重度提示</summary>

`checkStatus()` 是 `isVip() && isActivated()` 两个检查的短路与。只改一个，会走进 else 分支——**注意：那里弹出的字符串也以 `FLAG_18_L9{...}` 开头，那是诱饵**。把 `checkStatus()` 整体改成返回 true，或两个检查都改成返回 true。

</details>

<details>
<summary>关卡 10 · 中度提示</summary>

代码里 `verify()` 里有一个 64 位十六进制串（SHA-256）。口令是教程 20 主角的名字，全小写。也可以用 Frida 把 `HashCheckActivity.verify` 的返回值改成 true，输入随便什么都过。

</details>

<details>
<summary>关卡 11 · 中度提示</summary>

`MsgAuthActivity` 里密钥是 `fatdemo_hmac_key`，内置的是 HMAC-SHA256 结果。口令是 FATLAB 实验室代号全小写。Python 一行 `hmac.new(key, msg, hashlib.sha256)` 就能验。

</details>

<details>
<summary>关卡 12 · 重度提示</summary>

密钥、IV、密文都在 `SBox` 里（`FATDEMO_KEY_12AB` / `0001020304050607` / `Grg3J5v8Lh0r9KyE0Py0zw==`），`b1Activity` 只是调用它。用 Python 做一次 AES-CBC 解密就得到密码。注意旁边 `Md5Wrap`、`MiscCrypt` 是没人调用的诱饵。

</details>

<details>
<summary>关卡 13 · 重度提示</summary>

两个输入对应两段逻辑：账号走 `SignUtil`（MD5，内置哈希对应 `neon_user`），令牌走 `KBox`（AES-ECB，密钥 `NEON_TOKEN_KEY16`，解出 `neon_token_ok`）。两个都对才过。`HashFactory` 是诱饵。

</details>

<details>
<summary>关卡 14 · 重度提示</summary>

license 链路：`base64 → AES解密(密钥A在XBox) → AES解密(密钥B在Mux) → 异或0x5A → "GRANTED_2026_OK!"`。要用 Python 反向把明文一层层加密回去得到 license。deviceId 的 MD5 对应 `pivot_device`。`AesKit`、`Md5Tools`、`KeyFactory` 都是诱饵——尤其是 `KeyFactory` 里的假密钥，别拿它去算。

</details>

<details>
<summary>关卡 15 · 重度提示</summary>

1. 先跑 `python server.py`，再在 App 里输入页号 1 点"请求该页"看响应——签名参数 `sign` 由 `Sg`/`Kx` 拼出的密钥算 `HMAC-SHA256("page=N&ts=T")`。
2. 密钥拆成两段异或字节数组：`Kx.PA`（`^0x3C`）→ `fatdemo_`，`Sg.PB`（`^0x3C`）→ `page_key_2026`，拼起来就是完整密钥。
3. 用 Python 复刻签名，把 100 页全部取回求和（`TokenGen`/`DigestBox` 是诱饵，别管）。
4. 也可以 Frida 在 App 发包瞬间 Hook `Sg.sign`/`Mac.doFinal`/`java.net.URL` 看参数和 URL。

</details>

<details>
<summary>关卡 23 · 中度提示</summary>

1. 大厅点进去是**白屏**，不是坏了：页面是 `https://…:8443/h5/v23`（仅 HTTPS；主机由 NetHost 自动选：模拟器 `10.0.2.2` / 真机 `127.0.0.1`），服务端证书自签、没进系统信任库，App 在 `onReceivedSslError` 里 `handler.cancel()` 了。
2. 路径不在 config.json：`Hq` 类里有一段异或 `0x2F` 的字节数组，还原出来是 `/h5/v23`，主机由 `NetHost` 按环境拼。
3. 静态抄近道：`python server.py` 后 `curl -k https://127.0.0.1:8443/h5/v23`，页面 `#flag` 里就是 flag。
4. 动态正解：Frida Hook `com.fatdog.reverse.y3Activity$WvClient.onReceivedSslError`，调 `handler.proceed()` 放行——页面出现后 App 自动读 `#flag` 通关打点。

</details>

<details>
<summary>关卡 24 · 重度提示</summary>

1. 服务端 `python server.py` 后走 HTTPS:8443 的 `GET /api/swap`（主机由 NetHost 自动选）。HMAC 密钥两段：`Tk.PA`（^0x3C → `fatdemo_`）+ `Aw.KB`（^0x3C → `swap_key`），拼出 `fatdemo_swap_key`。
2. pin 没明文：`Z24Core.PINX` 异或 0x5A 还原出 `sha256/Tix1…`（和 L22 同一个服务器指纹）。注意 `Gp.FAKE_PIN` 是诱饵，别拿来换。
3. 反 Hook 守卫：`verify → Z24Core.checkPin`（guardTicks+1、记结论），响应前 `assertGuard()` 检查计数与结论——直接把 verify/checkPin Hook 掉放行，会抛"完整性校验失败"。
4. 正解（script E，内存换票）：第一关同 L21 换 TrustManager；第二关 Hook `Z24Core.realPin`，把返回值换成 mitmproxy 证书的 SPKI pin——校验链照常走完，计数正常、pin 也匹配。
5. 静态抄近道：还原 pin + HMAC 密钥后用 Python 带 `certs/ca.crt` 复刻请求（pinning 只保护 App 客户端，不拦 Python），100 页求和 = 50225。

</details>

<details>
<summary>关卡 25 · 中度提示</summary>

1. jadx 里只有声明：`Nx.verifyServer` / `Nx.nativeSign` 都是 `native` 方法，逻辑在 `libnative.so` 里（Java Hook 无用）。
2. 把 APK 里的 `lib/arm64-v8a/libnative.so` 解出来（APK 就是 zip），`strings libnative.so | grep fatdemo` → 密钥 `fatdemo_jni_2026`（本关特意放明文，native 逆向入门）。
3. 静态复刻：Python 带 `certs/ca.crt` 请求 `GET https://…:8443/api/native?page=N&ts=T&sign=HMAC-SHA256(fatdemo_jni_2026, "page=N&ts=T")`，100 页求和 = 52674。
4. 动态：Frida 原生层——`Interceptor.attach` 观察 `Java_com_fatdog_reverse_Nx_nativeSign` 的返回值，或用 `NativeFunction` 直接调它拿签名。
5. 注意 `Rj.FAKE_KEY` 是诱饵；`verifyServer` 只放行 10.0.2.2 / 127.0.0.1 / localhost。

</details>

<details>
<summary>关卡 20 · 重度提示</summary>

1. 进入关卡只有「点此领取 1 亿大礼包」——点了就弹**连环广告**：`switch(step)` 状态机一轮 8 条（5 张图循环复用），× 前 5 秒不显示、显示了点击瞬移四个角 + 嘲讽 Toast，连点 3 次出现「看完关闭」，点了进下一条……正常操作永远关不完。
2. 广告机在 `AdBox`：所有的文案都是异或 0x4D 的神秘数字，别去解文案；**真正要动的是开关字段 `a`**：
3. 正解：`apktool d FatdogReverse.apk -o out` → `out/smali/com/fatdog/reverse/AdBox.smali` → 把 `.field public static a:I = 0x1` 的 `0x1` 改成 `0x0`（或把 `showAd` 开头的 `sget v0, …->a:I` + `if-nez v0, :cond_?` 反转为 `if-eqz`）→ 回编译重签名重装 → 点按钮不再弹广告，页面出现「我已关掉广告」→ 礼花 + flag。
4. Frida 双解：`Java.use('com.fatdog.reverse.AdBox').a.value = 0;` 一跑，广告即断。
5. 注意 `PhantomAd.enabled` 是**诱饵假开关**：改它一点用没有——它的名字带 ad 但 AdBox 从不读它。

</details>

<details>
<summary>关卡 26 · 重度提示</summary>

1. 服务端 `python server.py` 后走 **HTTPS :8444** 的 `GET /api/mtls`（主机由 NetHost 自动选；8787/8443 上没有这个路由，绕不过去）。HMAC 密钥两段：`Zt.PA`（^0x3C → `fatdemo_`）+ `Vd.KB`（^0x3C → `mtls_key`），拼出 `fatdemo_mtls_key`。
2. 握手要**出示客户端证书**：APK 解开拿走 `assets/mt_client.p12`；打开密码拆在两个类——`Zt.PXA`（^0x37 → `fatdemo_`）+ `Mc.PXB`（^0x5B → `mt26`），拼出 `fatdemo_mt26`。注意 `MtlsKit.FAKE_PASS` 是诱饵，别拿来开 p12。
3. Python 复刻：用 cryptography 从 p12 里导出 client 证书+私钥，`ssl.create_default_context(cafile='certs/ca.crt')` + `load_cert_chain(crt, key)`，100 页求和 = **50814**。完整脚本见 SOLUTIONS.md 关卡 26。
4. 动态：Frida 调 `Mc.buildPassword()` 直接倒出 p12 密码，再用 mitmproxy 挂上客户端证书抓包。
5. 服务端证书由 `gen_certs.py` 重新生成时，App 内置的 CA/pin 会一起重烘焙（Tm/Pn/Z24Core 同步更新）。

</details>

<details>
<summary>关卡 27 · 重度提示</summary>

1. 入口 `c27Activity` 是全关唯一可读的类——跟进它的调用链会进到 `com.fatdog.reverse.p` 包，jadx 里这包已被 R8 改成 a/b/c 之类的短名：先靠交叉引用认出"加密原语/素材库/TLS 客户端/网络核心"四个角色。
2. 三把密钥各拆两半跨类拼装（全部 ^0x3C）：前缀 `fatdemo_` 在素材库 A，后缀 `aeskey27` / `fin_hmac` / `rspkey27` 在素材库 B；路径 `/api/l27` 是 ^0x25 数组，pin 是 ^0x27 数组（无明文 sha256/）。
3. 请求是 POST 表单：`enc=hex(AES-ECB(page=N&ts=T))`、`sign=HMAC-SHA256(enc)`，另有 client/chan/ver/dev 噪声字段；响应 `{"d": hex}` 用第三把 AES 密钥解密得 `page=N|nums=…`。
4. 抓包路线：Frida 同时放倒 TrustManager + CertificatePinner（或 objection 全家桶）——但 mitmproxy 里看到的仍是 enc 密文，想懂明文还得解密钥。
5. 静态正解：还原三把密钥后用 Python 带 `certs/ca.crt` 直接复刻 100 页取数求和 = **50623**。注意包内的 Gh 和根包的 EndKit 都是诱饵（假密钥假 pin），别拿来算。

</details>

<details>
<summary>关卡 28 · 中度提示</summary>

1. jadx 只有 `Zk.nativeSign` 声明；解包 APK 取 `lib/arm64-v8a/libl28.so`。
2. `strings libl28.so` 只见诱饵 `Fatdog_silent`——真密钥被 ^0x5C 存成字在数组 `KEY28_KX`（IDA 里读 `Zk_nativeSign` 的解码循环即还原 `Fatdog_unhappy`）。
3. 静态抄近道：Python 带 `certs/ca.crt` 复刻 HMAC 取 100 页求和 = 49750；动态：Frida 三联单看返回值对拍，或 `Memory.scanSync` 在运行时搜明文。

</details>

<details>
<summary>关卡 29 · 中度提示</summary>

1. 导出表的 `Java_com_fatdog_reverse_Wq_nativeSign` 是同名诱饵（假密钥 `Fatdog_lazy`，已被动态注册覆盖，Hook 它不会触发）；`Wq_sign` 返回废值。`Yd.FAKE_KEY` 也是假货。
2. 正解 spawn 注入：hook libart 的 `RegisterNatives`（`_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi`）打印映射，拿到真身地址 → 减模块基址得偏移 → Interceptor.attach 三联单。
3. 静态路线：IDA 从 `JNI_OnLoad` 的 RegisterNatives 参数找到无名真身与 `KEY29_KX`（^0x69 → `Fatdog_angry`），Python 复刻取数求和 = 50208。

</details>

<details>
<summary>关卡 30 · 中度提示</summary>

1. 导出表只有一个 `Java_com_fatdog_reverse_Vn_nativeSign`，内部经函数指针表派发到四个同形函数——IDA 里跟一次间接调用，找到 `K30_TABLE` 的四个槽位。
2. 四把密钥全是 UTF-16LE 码元数组（`unsigned short`）：`strings` 默认看不见；`strings -el libl30.so` 或在 IDA 数据窗按 16 位查看即现形。候选：gloomy(真)/pale/sour/mute，`Xk.FAKE_KEY=Fatdog_mute` 就是槽 3 假钥匙。
3. 静态抄近道：还原 `Fatdog_gloomy` 后 Python 复刻 HMAC 取数求和 = 51127；动态路线：按偏移 Hook 四候选逐个喂服务器验真（错的一律 403）。

</details>

<details>
<summary>关卡 31 · 中度提示</summary>

1. jadx 里搜不到 q.Ke——它被 R8 改名了。去 q 包里找带 `int[]` 码点表的类（{0x46,0x61,...} 就是 "Fatdog_"）；方法名 partA 因 native 回调被保留。
2. 抓包/hook 会看到每页 4 个同形 POST：只有响应里 nums 非空的是真包；错位包页号差 1、废签包签名是摆设、噪声包 enc 全零。Pw.FAKE_KEY=Fatdog_lovely 是一字之差陷阱。
3. 静态抄近道：拼出 Fatdog_lonely 后 Python 复刻 RC4+HMAC，只发真包取数求和 = 50768；动态：hook Zr.nativeEnc/nativeSign 直接拿现成参数。

</details>

<details>
<summary>关卡 37 · 中度提示</summary>

1. 症状：拿 hashlib.sha256(payload) 对拍一万次也不相等——不是算错，是这个 SHA-256 被"换过血"。
2. 认骨架：IDA 里 K 表开头 0x428a2f98（以字形态查看）说明压缩逻辑是标准 SHA-256；找改动点看初始化——h[] 来自派生值而非教科书常量。
3. 两处改动都要还原：IV = SHA256(Fatdog_dodge+"|iv")（整组 32 字节）；sign 外层再叠 RC4，钥 = SHA256(Fatdog_dodge+"|rc4")[:16]。strings -el 拿 Fatdog_dodge 后照 server.py 的 sha37_iv/rc4_37 抄即可。
4. 静态抄近道：Python 复刻变体取数求和 = 51242。Sc.FAKE_KEY=Fatdog_drift 是动词陷阱。

</details>

<details>
<summary>关卡 36 · 中度提示</summary>

1. strings libl36.so 找到 24 字符、以 == 结尾的 Base64 串（tE5zEyf1b+fe49uJN4cY7w==）——它就是藏宝图：base64 解码即得 16 字节 AES-128 钥匙。
2. IDA 认算法看 S 盒开头 63 7c 77 7b；真身 k36_ecb 经指针表派发在文件底部，前面 k36_fake_* 全是无人调用的诱饵。
3. 协议：enc=hex(AES-ECB(key,"page=N&ts=T" 零填充))、sign=HMAC-SHA256(mac,enc)，mac 由 Fatdog_break+"|mac" 运行时派生。Oo.FAKE_KEY=Fatdog_bluff 是一字之差陷阱。
4. 静态抄近道：Python 用 pycryptodome AES-ECB 复刻取数求和 = 49495。

</details>

<details>
<summary>关卡 35 · 中度提示</summary>

1. strings -el libl35.so 先拿到标记 Fatdog_sneak（UTF-16 存放）；两把钥匙都由它派生：SHA256("Fatdog_sneak|sm4")[:16] 与 SHA256("Fatdog_sneak|3des")[:24]。Kq.FAKE_KEY=Fatdog_skulk 是一字之差陷阱（命中即 403）。
2. IDA 认算法看魔数：DES 的 S1 盒开头 14,04,0d,01 与 PC1/PC2 表；SM4 的 S 盒开头 d6,90,e9,fe 与 FK a3b1bac6。真身 k35_sm4_ecb/k35_des3_ecb 经函数指针表派发，前面一堆 fake_*/junk_* 全是无人调用的诱饵（它们反而被导出了，正好当噪音）。
3. 协议：e1=hex(SM4(key,"page=N&ts=T" 零填充))、e2=hex(3DES(key,大端 ts))、sign=HMAC(Fatdog_sneak, e1+"|"+e2)。每页三连包只有响应 nums 非空的是真包。
4. 静态抄近道：Python 复刻双算法取数求和 = 51217（服务端 sm4_decrypt 与 pycryptodome DES3 可直接对照）。

</details>

<details>
<summary>关卡 34 · 重度提示</summary>

1. jadx：Yh 五个方法全是声明（真身动态注册）；导出表只有 JNI_OnLoad + 两个废诱饵 + K34_ZONE 锚点。strings -el 只见 UTF-16 的 Fatdog_grumpy——但光有它不够：参数走 Feistel8、响应是 RC4 密文。
2. 算法三件套（IDA 从 k34_pack/k34_sign/k34_unwrap 读）：enc=hex(Feistel8(key,payload))、sign=HMAC(key,enc)、响应 rsp_key=SHA256(key+"|rsp")[:16] 再 RC4。Feistel 轮函数 F_i=SHA256(sub_i||x)[:4]，sub_i=SHA256(key+str(i))[:4]，8 轮、零填充到 8 字节倍数。
3. 路线一（Frida）：spawn 下 hook JNI_OnLoad onEnter 抢先装钩子 → libart RegisterNatives 抓映射 → 偏移观察三联单拿现成 enc/sign/d 解包结果 → 复刻或直接转发。
4. 路线二（patch）：定位 k34_scan_once/k34_crc_ok 改字节废守卫。路线三（unidbg）：so 不回调 Java，补环境最省——离线喂 page/ts 直接收 enc/sign。
5. Python 全复刻参考 SOLUTIONS 关卡 34；100 页求和 = 49932。Ak.FAKE_KEY=Fatdog_sore 是一字之差陷阱。

</details>

<details>
<summary>关卡 33 · 中度提示</summary>

1. 症状：任何 Frida 钩子一挂（哪怕只 attach 观察不出手），签名立刻全错、App 报"完整性校验失败"——so 在给自己做 CRC 体检。
2. 线索：libl33.so 导出表里有两个空函数 `K33_ZONE_START/K33_ZONE_END`——它们之间的区间被排除在 CRC 外（校验器 k33_check 就住里面，这就是能安全 hook 它的原因）。
3. 三条正解任选其一：① spawn 下 hook JNI_OnLoad 的 onEnter 先装完所有钩子再放行（基线带钩建立，永远一致，最优雅）；② 偏移 hook k33_check 恒返回 1；③ Memory.scanSync 找 g_baseline 四字节写当前实值。整体替换 nativeSign 会被 assertGuard 记账抓包（ticks 踏步）。
4. 静态抄近道：strings -el 拿 Fatdog_jealous 直接 Python 复刻取数求和 = 49502。

</details>

<details>
<summary>关卡 32 · 中度提示</summary>

1. 症状：一挂 Frida 就所有页请求失败，且 App 弹过一次"环境异常警告"——这是 native 哨兵在投毒（密钥被改一个字节），不是网络问题。
2. 四路哨兵：maps 搜 frida/gadget、试连 27042/27043、线程名 gum-js-loop/gmain/gdbus、TracerPid 非 0。ptrace 占坑只挡 gdb。
3. 拆法任选：frida-server 改名换端口 + strongR-frida 洗指纹；或 IDA 找扫描函数按偏移 hook 成空操作；或 hook fopen/fgets 给 maps/status 洗地。
4. 静态抄近道：完全不碰运行时——strings -el 拿到 Fatdog_anxious 后 Python 复刻 HMAC 取数求和 = 51745。

</details>

## 路线图

- 第一季：教程 18 静态分析 6 关 + 教程 19 smali 4 关（7/8/9/20）+ 教程 20 Frida 5 关（10-14）+ 网络取数 5 关（15-19）
- 第二季：SSL / 抓包对抗系列 21-27（已全部落地，规划见 `PLANNED.md`）
- 第三季：native 层系列（L28-L37 十关已全部落地；后续新关卡规划见 PLANNED.md）；大厅新增「Native 试炼」分区
- **标记变更（自 L28 起）**：密钥/口令等标记弃用 `fatdemo_` 前缀，改用 `Fatdog_<情绪词>`（情绪词用尽换动词，如 `Fatdog_unhappy` / `Fatdog_sneak`）；L1-27 保持不变，完整规范见 `SKILL.md` §四