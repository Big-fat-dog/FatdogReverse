# FatdogReverse 开发规划与状态 —— 网络系列（15-25）

> 状态：**15-25 已全部落地**。关卡 20 已由"goto 地狱"整改为**万恶广告劫**（连环牛皮癣广告 + smali 改开关），见 README/SOLUTIONS。
> 设计目标：**数据只能发包拿**（数字/答案只在本地服务端 `server.py`，APK 里没有）；**加密在请求参数里**；**加密位置藏深**（密钥异或拼装 + 跨多类 + 诱饵类 + 真请求触发）。关卡 20 不取数，是一道"改 smali 开关"的独立题型。

## 通用架构（15-22、24-25 沿用，23 独立）

- **服务端**：`server.py`（FastAPI + uvicorn + pycryptodome），HTTP 监听 `127.0.0.1:8787`（15-20），HTTPS 监听 `127.0.0.1:8443`（21-25，自签 CA，证书由 `gen_certs.py` 生成在 `certs/`，不入 APK）。
  - 地址自动切换：`NetHost` 探测环境——模拟器自动走 `10.0.2.2`，真机自动走 `127.0.0.1`（识别不出模拟器特征时按真机）；`config.json` 的 `api_base_url` 默认 `"AUTO"`，填局域网 IP 可覆盖。
  - 真机：`adb reverse tcp:8787 tcp:8787`（8443 同理）；或电脑防火墙放行 + 局域网 IP 覆盖，免 USB。
- **客户端**：15-20 用 `HttpURLConnection`，21-22、24-25 用 OkHttp；加密/签名只在发包瞬间执行。
- **flag 交付**：15-22、24-25 的 flag 硬编码在 App 内（提交正确加和后 Celebration 展示）；**23 的 flag 只存在于服务端 H5 页面里，APK 完全没有**。
- **藏深手段**：密钥/IV 以异或字节数组拆段分散在多个类中运行时拼装；一关横跨 3-4 个真实类 + 1-3 个诱饵类；L19 的加密包还过了真 R8 混淆（类改名 + 字符串异或）。

## 落地总表

| 关卡 | 名称 | 算法/签名 | 端点 | 加和 | flag |
|---|---|---|---|---|---|
| 15 | 千数求和 | HMAC-SHA256 | GET /api/page | 49580 | FLAG_18_L15{thousand_number_sum} |
| 16 | 流密码暗河 | RC4 双向 + MD5 | GET /api/rc4 | 24074 | FLAG_18_L16{rc4_stream_encrypted} |
| 17 | 玄门遁甲 | SM4 参数 + SM3 签名 | POST /api/form | 50636 | FLAG_18_L17{sm4_sm3_form} |
| 18 | 乾坤密钥 | RSA 加密参数 + DES 解密响应 | GET /api/dskey + POST /api/rsa | 51258 | FLAG_18_L18{rsa_des_form} |
| 19 | 雾里看花 | AES 参数 + HMAC，响应加密，o 包 R8 混淆 | POST /api/l19 | 51648 | FLAG_18_L19{obfuscated_aes_hmac} |
| 21 | 踏云寻踪 | HMAC-SHA256 + 自定义 TrustManager | GET https://…/api/tls | 51496 | FLAG_18_L21{tls_custom_trust} |
| 22 | 双锁封疆 | HMAC-SHA256 + TrustManager + OkHttp Pinner 双闸门 | GET https://…/api/pin | 50384 | FLAG_18_L22{okhttp_certificate_pinner} |
| 23 | 白屏迷雾 | 无加密：自签证书错误 → onReceivedSslError cancel → 白屏 | GET https://…/h5/v23（仅 HTTPS，HTTP 403） | — | FLAG_18_L23{webview_ssl_error}（只在服务端页面） |
| 24 | 换票迷局 | HMAC-SHA256 + TrustManager + HostnameVerifier pin 校验 + 反 Hook 守卫 | GET https://…/api/swap | 50225 | FLAG_18_L24{anti_hook_pin_swap} |
| 25 | 灵台证真 | HMAC-SHA256 全在 native（libnative.so）算 + JNI 主机门禁 verifyServer | GET https://…/api/native | 52674 | FLAG_18_L25{native_jni_verify} |

> 加和 = 全部页数字的总和，App 用内置校验比对通过后才展示 flag。

## 每关类分布（真实类 + 诱饵）

- L15：`s5Activity` + `Sg` + `Kx`（诱饵 `TokenGen`/`DigestBox`）
- L16：`t6Activity` + `C16` + `Rc4Core` + `Jk`（诱饵 `B64Kit`/`TokenGen`/`DigestBox`）
- L17：`u7Activity` + `Fl` + `Kt` + `Sm4Core` + `Sm3Core`（诱饵 `NetPacker`）
- L18：`v8Activity` + `Rs` + `Pk`（诱饵 `RsaKit`）
- L19：`v9Activity` + `o/Api` + `o/Encrypt` + `o/Keys` + `o/Dummy`（o 包被 R8 重命名为 a/b/c/d）
- L21：`w1Activity` + `Tm` + `Km`（诱饵 `CertBox`）
- L22：`x2Activity` + `Pn` + `Kp`（诱饵 `Pim`）
- L23：`y3Activity` + `Hq`（诱饵 `WvKit`）
- L24：`z24Activity` + `Aw` + `Tk` + `Z24Core`（诱饵 `Gp`）
- L25：`a25Activity` + `Nx` + `By` + `libnative.so`（诱饵 `Rj`）

## 关卡 20 设计明细（万恶广告劫：改 smali 关弹窗）

- **玩法（对玩家）**：进关卡只有一个「点此领取 1 亿大礼包」→ 点了就弹全屏连环广告：
  `AdBox.showAd` 用 `switch(step)` 状态机一轮 8 条（5 张广告图 + 循环复用），× 前 5 秒不显示、
  显示后点击瞬移四角 + 嘲讽 Toast、连点 3 次出现「看完关闭」，进了下一条——正常操作永远关不掉。
- **App 端**：
  - `a20Activity`：关卡页（领取按钮 +「我已关掉广告」成功区，成功才触发 `Celebration.show` + `PassLog.mark("L20")`）。
  - `AdBox`：广告机。**唯一真开关 `public static int a = 1`**（smali 里 `.field a:I = 0x1`）；文案全部异或 0x4D
    藏在 `T0..T7/G0..G7/TAUNTS` 等数组（jadx 全是神秘数字，smali 只是 const 数组）；`showAd` 开头 `sget a + if-nez` 一眼可见。
  - `switch(step)` 编译成 **packed-switch**（Case 0-7 连续，已确认 smali 数据区 `.packed-switch 0x0` 8 个标签）。
  - `PhantomAd`（诱饵）：名字带 ad 不起眼，`enabled=1` 假开关，改它没用。
  - `Sx`：XOR 字符串还原工具。
- **破解点**：
  - 正解（apktool）：`AdBox.smali` 的 `.field public static a:I = 0x1` 改 `0x0`，或 `showAd` 的 `if-nez` 反转为 `if-eqz`；回编译重签名安装。
  - 双解（Frida）：`Java.use('com.fatdog.reverse.AdBox').a.value = 0;`
  - 干扰：改 `PhantomAd.enabled` 无效、解 XOR 文案无效、改 `step` 无效。
- **入口/配套**：大厅 `btn_ad20`（"关卡 20：万恶广告劫"，归入 Smali 分类组，位于 btn_l19 与 btn_t21 之间）；
  Manifest `.a20Activity`；`ad_01..05.jpg`（由 `图库/` 5 张图转码进 `res/drawable-nodpi`）；
  神念自察 L20 功法改为「广告心魔 / 万恶广告劫：smali 改一个开关，心魔退散，广告再不打扰」；太古禁地 L20 层标题「第 20 层 · 万恶广告劫」。
- **工程变化**：删除 `app/smali/` 与 `gen_g8_smali.py`，`build_apk.py` 移除 smali 汇编步骤 → **APK 只含单 classes.dex**，产物 `FatdogReverse.apk`；flag `FLAG_18_L20{ads_are_gone}`。

## 关卡 23 设计明细（WebView 白屏）

- **App 端**：
  - `Hq`：路径 `/h5/v23` 以异或 `0x2F` 字节数组保存，主机由 `NetHost.httpsBase()` 按环境拼（模拟器 `10.0.2.2` / 真机 `127.0.0.1`）；不依赖 config.json 的 HTTP 基址。
  - `y3Activity`：WebView 加载该 URL；内部类 `WvClient.onReceivedSslError` 直接 `handler.cancel()` → 白屏（状态栏显示"证书校验失败：页面白屏"）。
  - 页面加载成功后 `onPageFinished` 用 `evaluateJavascript` 读 H5 的 `#flag` 文本，触发 `Celebration.show` + `PassLog.mark("L23")`。
  - `WvKit`：诱饵工具类，无人调用。
- **服务端**：`GET /h5/v23` 仅接受 HTTPS（HTTP 请求 403），返回含 `<span id="flag">FLAG_18_L23{webview_ssl_error}</span>` 的页面。
- **破解点**：
  - 静态：jadx 看 `Hq` 异或还原路径 `/h5/v23`；`curl -k https://127.0.0.1:8443/h5/v23` 直接看 flag。
  - 动态：Frida Hook `com.fatdog.reverse.y3Activity$WvClient.onReceivedSslError` → `handler.proceed()`。
- 完整题解见 `SOLUTIONS.md` 末尾。

## 关卡 24 设计明细（反 Hook 检测 + 内存换 pin）

- **App 端**：
  - `z24Activity`：关卡页（100 页×10 个分页取数求和，内置 `SUM_HASH` 校验，banner 用 `drawable-nodpi/level_24.gif`）。
  - `Aw`：OkHttp 客户端。自定义 TrustManager 只信内置 CA（复用 `Tm.caDer()`）；`HostnameVerifier.verify` 计算服务器证书 SPKI → `Z24Core.checkPin`；响应解析前调 `Z24Core.assertGuard()`。
  - `Z24Core`：pin 以 `^0x5A` 字节数组隐藏（无明文 `sha256/`）；`checkPin` 先 `guardTicks++` 并记 `lastVerdict` 再比较；`assertGuard` 发现计数为 0 或结论为假就抛"完整性校验失败：校验链被篡改"。
  - `Tk` + `Aw.KB`：HMAC 密钥两段拼装 `fatdemo_swap_key`，请求 `GET /api/swap?page=N&ts=T&sign=HMAC(...)`。
  - `Gp`：诱饵（假 pin + 假放行，无人调用）。
- **服务端**：`GET /api/swap` 验 page/ts/sign（KEY24_HMAC），返回明文 JSON；SEED24=20261224，1000 个数字总和 50225。
- **破解点**：
  - 翻车打法：Hook `verify`/`checkPin` 强制放行 → 守卫抛异常（页面显示"完整性校验失败"）。
  - 正解（script E）：Frida Hook `Z24Core.realPin` 返回 mitmproxy 证书的 SPKI pin（内存换票），配合 L21 的 TrustManager 替换，流量全过代理。
  - 静态抄近道：还原 XOR（pin + 密钥）后用 Python 带 `certs/ca.crt` 直接复刻取数（pinning 只保护 App 客户端）。
- 完整题解见 `SOLUTIONS.md`（关卡 24）。

## 关卡 25 设计明细（native 校验 / JNI，教程 22 预告）

- **App 端**：
  - `a25Activity`：关卡页（100 页×10 个分页取数求和，内置 `SUM_HASH` 校验，banner 用 `drawable-nodpi/level_25.jpg`）。
  - `Nx`：JNI 桥（`System.loadLibrary("native")`），只有 `verifyServer` / `nativeSign` 两个 native 声明。
  - `By`：OkHttp 客户端。发请求前先 `Nx.verifyServer(NetHost.host())`（native 主机白名单），签名 `Nx.nativeSign(page, ts)`；TLS 用内置 CA（复用 `Tm.caDer()`），HostnameVerifier 也走 native 门禁。
  - `libnative.so`（`app/jni/native.c`）：`verifyServer`（C 里 strcmp 白名单 10.0.2.2/127.0.0.1/localhost）+ `nativeSign`（C 里实现 SHA-256/HMAC-SHA256，密钥 `fatdemo_jni_2026` **明文全局符号**——strings 可见；本关是 native 逆向入门，刻意不加 XOR）。
  - `Rj`：诱饵（Java 层假密钥，无人调用）。
- **服务端**：`GET /api/native` 验 page/ts/sign（KEY25_HMAC），返回明文 JSON；SEED25=20270115，1000 个数字总和 52674。
- **破解点**：
  - Java 层 Hook 无效：签名不在 Java 算（Hook Mac/MessageDigest 看不到东西），jadx 也看不到密钥。
  - 静态正解：解出 `libnative.so`，`strings` 拿密钥 → Python 带 CA 复刻取数。
  - 动态正解：Frida 原生层 `Interceptor.attach` 观察 / `NativeFunction` 直接调 `nativeSign`；也可 patch so 改白名单。
- 完整题解见 `SOLUTIONS.md`（关卡 25）。

## 实现清单（每关落地时已做）

1. `server.py` 加对应接口（验签/加解密/页面逻辑只在服务端，数字/flag 不进 APK）。
2. App 加关卡类（难读类名 + 工具类拆分 + 诱饵类），请求触发加密；网络地址统一由 `NetHost` 按环境选择。
3. `AndroidManifest.xml` / `MainActivity` / `strings.xml` / `view_levels.xml` / `DivineReflectionActivity`（神念自察功法名）/ `ProfileActivity`（境界）同步。
4. 重建 APK，抽查类与资源。
5. 更新 `README.md` / `SOLUTIONS.md` / `REPORT.md` / 本文件。

## 后续规划

- 第三季：教程 22 native 层逆向——可考虑把某关校验挪进 `libnative.so`。
- 可选加料：签名校验防重打包、root/模拟器检测、flag 全部改服务端下发。
