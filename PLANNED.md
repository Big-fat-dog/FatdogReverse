# FatdogReverse 开发规划与状态 —— 网络系列（15-26）+ 万法归宗（27）

> 状态：**15-27 与第三季 L28-29 已全部落地**。关卡 20 已由"goto 地狱"整改为**万恶广告劫**（连环牛皮癣广告 + smali 改开关），见 README/SOLUTIONS。
> 设计目标：**数据只能发包拿**（数字/答案只在本地服务端 `server.py`，APK 里没有）；**加密在请求参数里**；**加密位置藏深**（密钥异或拼装 + 跨多类 + 诱饵类 + 真请求触发）。关卡 20 不取数，是一道"改 smali 开关"的独立题型；关卡 27 把 HTTPS 双闸门与复合签名合成一关。

## 通用架构（15-22、24-27 沿用，23 独立）

- **服务端**：`server.py`（FastAPI + uvicorn + pycryptodome），HTTP 监听 `127.0.0.1:8787`（15-20），HTTPS 监听 `127.0.0.1:8443`（21-25、27，自签 CA，证书由 `gen_certs.py` 生成在 `certs/`，不入 APK），mTLS 监听 `127.0.0.1:8444`（26）。
  - 地址自动切换：`NetHost` 探测环境——模拟器自动走 `10.0.2.2`，真机自动走 `127.0.0.1`（识别不出模拟器特征时按真机）；`config.json` 的 `api_base_url` 默认 `"AUTO"`，填局域网 IP 可覆盖。
  - 真机：`adb reverse tcp:8787 tcp:8787`（8443 同理）；或电脑防火墙放行 + 局域网 IP 覆盖，免 USB。
- **客户端**：15-20 用 `HttpURLConnection`，21-22、24-25 用 OkHttp；加密/签名只在发包瞬间执行。
- **flag 交付**：15-22、24-27 的 flag 硬编码在 App 内（提交正确加和后 Celebration 展示）；**23 的 flag 只存在于服务端 H5 页面里，APK 完全没有**。
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
| 26 | 双符合璧 | 双向 TLS（mTLS）：握手层强制客户端证书 + PKCS12 密码拆分 + HMAC | GET https://…:8444/api/mtls | 50814 | FLAG_18_L26{mutual_tls_client_cert} |
| 27 | 万法归宗 | HTTPS 双闸门（TrustManager+Pinner）+ 复合签名：AES 参数 + HMAC + 响应加密，加密包 R8 混淆 | POST https://…/api/l27 | 50623 | FLAG_18_L27{capture_then_replicate} |
| 28 | 缄默之钥 | HMAC-SHA256，密钥 ^0x5C 异或藏进 libl28.so 的 .rodata（strings 只有诱饵 Fatdog_silent） | GET https://…/api/l28 | 49750 | FLAG_18_L28{runtime_decoded_key} |
| 29 | 隐姓埋名 | HMAC-SHA256，真身经 JNI_OnLoad 动态注册绑定（无名 static 函数；导出表两个假 nativeSign 全是坑） | GET https://…/api/l29 | 50208 | FLAG_18_L29{register_natives_caught} |
| 30 | 无名剑冢 | HMAC-SHA256，四同形签名函数经函数指针表派发（间接调用模糊 xref）；密钥 UTF-16LE 码元藏匿（默认 strings 盲区） | GET https://…/api/l30 | 51127 | FLAG_18_L30{nameless_dispatch} |
| 31 | 两界穿针 | RC4 加密参数 + HMAC 签名；密钥跨层拼装（Java q 包 R8 改名类持 Fatdog_，so 持 UTF-16 lonely，native 回调取件）；每页连发 4 个同形包（1 真 + 错位/废签/噪声） | POST https://…/api/l31 | 50768 | FLAG_18_L31{cross_layer_key} |
| 32 | 心魔哨兵 | HMAC-SHA256 + 四路反检测哨兵（maps/端口/线程名/TracerPid + ptrace 占坑）；中招静默投毒一字节，App 弹一次警告不封禁 | GET https://…/api/l32 | 51745 | FLAG_18_L32{silent_poison_defused} |
| 33 | 金刚不坏 | HMAC-SHA256 + 自完整性校验（可执行段 CRC32 基线比对，校验器区间挖洞排除）+ 记账守卫防整体替换；三解全开（JNI_OnLoad 抢跑 / hook 校验器 / 改基线） | GET https://…/api/l33 | 49502 | FLAG_18_L33{crc_guard_bypassed} |
| 34 | 万法归墟 | 综合卷：动态注册 + 无名 Feistel8 参数加密 + HMAC 签名 + 四路哨兵 + CRC 自校验 + 记账守卫 + 响应 RC4（密钥派生）；三条官方路线（Frida/patch/unidbg） | POST https://…/api/l34 | 49932 | FLAG_18_L34{guixu_all_in_one} |
| 35 | 双匣暗渡 | 手写 3DES+SM4（魔数认阵：S1 盒/FK·CK/S 盒），文件前半诱饵函数垫底、真身指针表派发；双密文参数 e1/e2 + 动态 ts；每页三连包辨真假 | POST https://…/api/l35 | 51217 | FLAG_18_L35{sbox_tells_all} |
| 36 | 查表识君 | 手写 AES-128（S 盒 637c777b…）沉底派发；钥匙藏 .rodata 的 Base64 串（解码即 16 字节真钥——Base64 不是加密）；enc=hex(AES-ECB)+sign=HMAC(mac) | GET https://…/api/l36 | 49495 | FLAG_18_L36{base64_is_not_encryption} |
| 37 | 雪崩之谜 | 手写 SHA-256 变体：压缩轮/K 表与标准一致但初始 IV 整组换血（SHA256(Fatdog_dodge+"|iv") 派生），摘要再叠 RC4（同法派生钥）→ hashlib 永远对不上；认骨架看 K 表、找改动看初始化 | GET https://…/api/l37 | 51242 | FLAG_18_L37{avalanche_hides_the_blood} |

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
- L26：`b26Activity` + `Vd` + `Mc` + `Zt` + `assets/mt_client.p12`（诱饵 `MtlsKit`）
- L27：`c27Activity` + `p/Wire` + `p/Gate` + `p/Cpt` + `p/Mk` + `p/Tail`（诱饵：包内 `p/Gh` + 根包 `EndKit`）
- L28：`d28Activity` + `Zk` + `Ct` + `libl28.so`（诱饵 `Fk`；so 内另埋明文诱钥 `Fatdog_silent`）
- L29：`e29Activity` + `Wq` + `Xs` + `libl29.so`（诱饵 `Yd`；so 导出表只有 JNI_OnLoad 与两个假 nativeSign）
- L30：`f30Activity` + `Vn` + `Wo` + `libl30.so`（诱饵 `Xk`；so 内四个同形签名函数 + UTF-16 密钥库，导出仅一个 JNI 入口）
- L31：`g31Activity` + `Zr`（JNI 桥）+ `Xd`（干扰包分发器）+ `q/Ke`（R8 改名的 Java 半截）+ `libl31.so`（诱饵 `Pw`）
- L32：`h32Activity`（含环境异常警告窗）+ `Bt`（JNI 桥：nativeSign/isPoisoned）+ `Cm` + `libl32.so`（诱饵 `Dn`；so 内四路哨兵守护线程）
- L33：`i33Activity` + `Fh`（nativeSign/assertGuard/isPoisoned）+ `Gi`（发包前过记账守卫）+ `libl33.so`（诱饵 `Hk`；K33_ZONE_START/END 锚点即 CRC 挖洞线索）
- L34：`j34Activity` + `Yh`（五方法全动态注册：pack/sign/unwrap/assertGuard/isPoisoned）+ `Zi`（POST + 响应解包）+ `libl34.so`（诱饵 `Ak`；导出仅 JNI_OnLoad + 双诱饵 + 区间锚点）
- L35：`k35Activity` + `Ir`（nativeEncSm4/nativeEncDes/nativeSign，静态注册）+ `Js`（三连包分发器）+ `libl35.so`（诱饵 `Kq`；so 内四个诱饵变换函数可见导出——按设计当噪音）
- L36：`l36Activity` + `Mn`（nativeEnc/nativeSign）+ `Nn`（GET 客户端）+ `libl36.so`（诱饵 `Oo`；K36_KEY_B64 明文可见即藏宝图）
- L37：`m37Activity` + `Qa`（nativeSign）+ `Rb`（GET 客户端）+ `libl37.so`（诱饵 `Sc`；导出 JNI_OnLoad/Qa_nativeSign/三诱饵函数）

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

## 关卡 27 设计明细（万法归宗：抓包→复刻全环）

- **玩法（对玩家）**：把 21/22 的双闸门和 19 的复合签名合到一关：HTTPS + pinning 挡在门外，
  请求参数 AES 整段加密 + HMAC 签名、响应体再加密。**抓到明文≠采集成功**，必须复刻整条签名链才能取满 100 页。
- **App 端**：
  - `c27Activity`：关卡页（100 页×10 个分页取数求和，内置 `SUM_HASH` 校验，banner 用 `drawable-nodpi/level_27.jpg`）。
    本类保持可读——它是玩家顺藤摸瓜进混淆包的入口（同 L19 的 v9Activity 定位）。
  - `p/Wire`：网络核心。`enc = hex(AES(req_key,"page=N&ts=T"))`、`sign = HMAC(hmac_key, enc)`，POST 表单带
    page/ts/enc/sign/client/chan/ver/dev 噪声字段；响应 `{"d": hex}` 用 rsp_key 解密成 `page=N|nums=…`。
  - `p/Gate`：OkHttp 双闸门。TrustManager 复用 `Tm.caDer()`；CertificatePinner 的 pin 以 `^0x27`
    字节数组藏在 `Mk`（无明文 `sha256/`）；HostnameVerifier 按 `NetHost.host()` 动态放行。
  - `p/Cpt`：加密原语（AES-ECB/PKCS5 + HmacSHA256 + hex），算法名异或 `^0x31` 藏在 Mk。
  - `p/Mk` / `p/Tail`：三把密钥各拆两半跨类拼装——`fatdemo_`（^0x3C，Mk）+ `aeskey27`/`fin_hmac`/`rspkey27`（^0x3C，Tail）
    = `fatdemo_aeskey27` / `fatdemo_fin_hmac` / `fatdemo_rspkey27`；路径 `/api/l27` 异或 `^0x25` 藏 Mk。
  - **R8**：整个 p 包不在 r8.pro 的 keep 名单里，构建时自动改名（与 L19 的 o 包同一机制）。
  - 诱饵双份：包内 `p/Gh`（假密钥假 pin，跟着一起被混淆）+ 根包 `EndKit`（假密钥假端点 `/api/end`，可读更像真的）。
- **服务端**：主 app 加 `POST /api/l27`（8443 上跑，8787 同路由不拦——pinning 只保护 App 客户端，静态复刻本就直连）。
  验 ts 窗口 → 验 HMAC(sign==HMAC(enc)) → AES 解 enc 得 `page=N&ts=T` 且与表单一致 → 返回 AES 加密 body。
  SEED27=20270227，1000 个数字总和 50623。
- **破解点**：
  - 抓包路线：Frida 同时放倒 TrustManager（换信任系统/mitmproxy CA）+ CertificatePinner.check（或 objection 全家桶）→
    mitmproxy 看到的也只是 enc 密文——还得解出三把密钥才能懂明文。
  - 静态正解：jadx 从 c27Activity 跟进被改名的 p 包 → 还原三组 XOR（0x3C/0x25/0x31/0x27）拼齐密钥与路径 →
    Python 带 `certs/ca.crt` POST 复刻 100 页取数（完整脚本见 SOLUTIONS 关卡 27）。
- **注意**：`gen_certs.py` 重生成证书后，L27 的 pin（`Mk.S_PIN` ^0x27）也要随 Tm/Pn/Z24Core 一起重烘焙。

## 关卡 28 设计明细（缄默之钥：native 字符串加密，已落地）

- **App 端**：`d28Activity`（分页取数求和模板，banner level_28.jpg）＋ `Zk`（JNI 桥，loadLibrary("l28")）＋ `Ct`（OkHttp，信任 Tm.caDer()，GET /api/l28?page=N&ts=T&sign=…）。
- **libl28.so**：密钥 `Fatdog_unhappy` 以 ^0x5C 数组躺 .rodata（非 static 全局 `KEY28_KX`，防编译器折叠进指令）；`Zk.nativeSign` 运行时解到栈缓冲喂 HMAC-SHA256，消息 `page=N&ts=T`。诱饵三件：Java 层 `Fk.FAKE_KEY="Fatdog_silent"`、so 明文 `KEY28_DECOY` 同值。
- **服务端**：`GET /api/l28` 验签（KEY28_HMAC=Fatdog_unhappy），SEED28=20270315，加和 49750。
- **破解点**：① IDA 读解码循环还原密钥 → Python 复刻；② Frida 三联单观察返回值对拍；③ Memory.scanSync 运行时搜解出的明文。注意别拿 Fk/DECOY 的假钥算。

## 关卡 29 设计明细（隐姓埋名：native 动态注册，已落地）

- **App 端**：`e29Activity` ＋ `Wq`（声明 nativeSign，loadLibrary("l29")）＋ `Xs`（OkHttp 客户端，GET /api/l29）。
- **libl29.so**：`JNI_OnLoad` 里 `RegisterNatives` 把 `Wq.nativeSign` 绑到 static 无名函数 `l29_real_sign`（strip 后导出表彻底无名）；密钥 `Fatdog_angry` 以 ^0x69 数组藏 `.data`（非 const 全局 `KEY29_KX`，防常量折叠成明文字面量——实测踩过这坑）。
- **双诱饵导出**：`Java_com_fatdog_reverse_Wq_nativeSign`（名字完全符合静态注册规则但被动态覆盖，JVM 永不调用；内部用明文假钥 `Fatdog_lazy`，strings 可见）；`Java_com_fatdog_reverse_Wq_sign`（方法名都对不上，返回固定废 hex）。按名 Hook 前者不触发、手动 NativeFunction 调它得错值 → 服务器 403。
- **服务端**：`GET /api/l29` 验签（KEY29_HMAC=Fatdog_angry），SEED29=20270412，加和 50208。
- **破解点**：① spawn 注入 + hook libart `_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi` 抓映射拿真身地址 → 偏移 Hook 三联单；② IDA 从 JNI_OnLoad 参数顺藤摸瓜静态还原。

## 关卡 30 设计明细（无名剑冢：指针表派发 + UTF-16 藏钥，已落地）

- **App 端**：`f30Activity` ＋ `Vn`（声明 nativeSign，loadLibrary("l30")）＋ `Wo`（OkHttp 客户端，GET /api/l30）。
- **libl30.so**：四个 noinline 同形签名函数——gloomy(真)/pale/sour/mute，经 `K30_TABLE[4]` 函数指针表派发（volatile 槽位防常量折叠），JNI 入口只暴露一次间接调用；真身压在文件最底部。四把密钥全部以 **UTF-16LE 码元数组**存放（非 const 全局防折叠）：默认 `strings` 与 IDA 字符串窗口均不显示，`strings -el` 或数据窗看字节数组即现形。
- **服务端**：`GET /api/l30` 验签（KEY30_HMAC=Fatdog_gloomy），SEED30=20270520，加和 51127。
- **破解点**：① IDA 定位派发表与四个码元数组 → 还原 Fatdog_gloomy → Python 复刻；② 按偏移逐个 Hook 四候选观察返回值，服务器验真（错候选一律 403）；③ `strings -el libl30.so` 直接收 UTF-16 明文（本关教学点：编码藏匿挡不住 -el）。

## 关卡 31 设计明细（两界穿针：跨层拼装 + 干扰包，已落地）

- **App 端**：`g31Activity` ＋ `Zr`（JNI 桥：bindKeyClass/nativeEnc/nativeSign）＋ `Xd`（每页连发 4 个同形 POST 包的分发器）＋ `q/Ke`（Java 半截密钥，int[] 码点表；q 子包被 R8 整体改名，但 partA 方法名经 r8.pro 的 keepclassmembers 保留——native 要按名字回调它）。
- **libl31.so**：`JNI_OnLoad` 接住 JavaVM 存全局；`bindKeyClass(Class<?>)` 把 Ke 的 jclass 缓存成 GlobalRef（jclass 直传绕开 FindClass 按名查找，不怕 R8 改名）；每次 nativeEnc/nativeSign 都经 GetStaticMethodID → CallStaticObjectMethod → partA 取前半 "Fatdog_"，与 so 内 UTF-16 后半 "lonely" 拼成完整密钥。请求形态：`enc=hex(RC4(key,"page=N&ts=T"))`、`sign=HMAC(key,enc)`、动态 ts。
- **干扰包规格**：真包 + 错位包（表单页号与载荷差 1）+ 废签包（摆设签名）+ 噪声包（enc 全零），字段名完全一致。服务端裁决：真钥全对 → 返回数字；近亲假钥 Fatdog_lovely 命中 → 点名 403；其余一律 200 + `nums:[]`（形似而空，逼玩家靠内容分辨）。
- **服务端**：`POST /api/l31`（KEY31_HMAC=Fatdog_lonely），SEED31=20270618，加和 50768。
- **破解点**：① hook Zr.nativeEnc/nativeSign 拿现成参数直接复刻；② hook libart CallStaticObjectMethod 观察跨层取件；③ 静态：jadx 在改名后的 q 包里找 int[] 码点表 + IDA 读 KEY31_B 与 RC4，Python 只发真包取数。陷阱：Pw.FAKE_KEY=Fatdog_lovely 与真钥一字之差。

## 关卡 32 设计明细（心魔哨兵：native 反检测 + 静默投毒，已落地）

- **App 端**：`h32Activity` ＋ `Bt`（nativeSign / isPoisoned）＋ `Cm`（OkHttp 客户端，GET /api/l32）。onError 时查 `isPoisoned()`——首次命中弹"环境异常警告"窗（教学向：只警告，不拉黑不封号），之后照常运行。
- **libl32.so**：四路哨兵随 JNI_OnLoad 启动并起守护线程每 2s 轮询——① fopen/fgets 扫 /proc/self/maps 搜 frida/gadget；② connect 试探 127.0.0.1:27042/27043；③ opendir /proc/self/task 枚举线程 comm 找 gum-js-loop/gmain/gdbus；④ /proc/self/status 的 TracerPid 非 0 报警。另有 `ptrace(PTRACE_TRACEME)` 自占调试位（只挡 gdb/IDA attach，挡不了 Frida——教学点）。
- **静默投毒**：任一哨兵命中即置 g_poison，之后每次签名把密钥第 5 字节异或 0x01（Fatdog_anxious → Fatdng_anxious 一字之差），签名全错但 App 无任何崩溃表现。
- **服务端**：`GET /api/l32` 标准验签（KEY32_HMAC=Fatdog_anxious），SEED32=20270726，加和 51745。被投毒的签名自然全部 403。
- **破解点**：① 静态复刻党全程免疫（Python 直接算 Fatdog_anxious 的 HMAC）；② 动态党拆法三层——改名换端口 frida-server + strongR-frida 洗指纹 / IDA 定位 `k32_scan_once` 偏移 hook 成空函数 / hook fopen·fgets 给 maps 洗地（滤掉含 frida 的行、TracerPid 改 0）。

## 关卡 33 设计明细（金刚不坏：CRC 自校验 + 记账守卫，已落地）

- **App 端**：`i33Activity` ＋ `Fh`（nativeSign/assertGuard(minTicks)/isPoisoned）＋ `Gi`（OkHttp 客户端，发包前先过 assertGuard——整体替换 nativeSign 会因 ticks 踏步而现形）。onError 时 isPoisoned 首次命中弹"完整性校验失败"警告窗。
- **libl33.so**：`JNI_OnLoad` 用 dladdr 定位自身基址 → 解析 PT_LOAD/PF_X 段 → 对可执行段算 **CRC32 存 g_baseline**；每次 nativeSign 重算比对，不一致即投毒一字节（Fatdog_jealous→一字之差）。守护线程每 2s 复查。
- **挖洞设计**：CRC 计算挖掉 `K33_ZONE_START ~ K33_ZONE_END` 区间（校验器本体所在）——两个空函数锚点直接导出在符号表里，就是给 IDA 玩家的明示线索；也因此解法②（hook 校验器 k33_check）不会触发 CRC。
- **三条官方解法全开**：① spawn 下 hook JNI_OnLoad 于 onEnter 装完钩子（基线带钩建立永远一致）；② 按偏移 hook k33_check；③ Memory 找 g_baseline 写入当前实值。记账守卫另挡"整体替换"流。
- **服务端**：`GET /api/l33` 标准验签（KEY33_HMAC=Fatdog_jealous），SEED33=20270901，加和 49502。

## 关卡 34 设计明细（万法归墟：综合卷，已落地）

- **请求链**：POST 表单 page/ts/enc/sign(+dev/ver 噪声)；payload="page=N&ts=T" 零填充至 8 的倍数 → **Feistel8** 加密（轮函数 F_i(x)=SHA256(sub_i||x)[:4]，sub_i=SHA256(Fatdog_grumpy||str(i))[:4]）→ enc=hex；sign=HMAC-SHA256(Fatdog_grumpy, enc)。纯猜必死——必须还原 Feistel 或借用 oracle。
- **响应链**：{"d": hex(RC4(rsp_key,"page=N|nums=…"))}，rsp_key=SHA256("Fatdog_grumpy|rsp")[:16] 密钥派生；App 经 Yh.nativeUnwrap 在 native 解包。注意：派生种子必须运行时拼装——明文字面量会被 strings 一把梭（开发时踩过并已修复）。
- **守卫全家桶**：JNI_OnLoad 里 ptrace 占坑 → RegisterNatives 动态注册五个真身（static 无名）→ CRC 建基线（K34_ZONE 挖洞）→ 起四路哨兵守护线程；任一失守静默投毒一字节 + App 弹一次警告。
- **诱饵**：导出表 Java_com_fatdog_reverse_Yh_nativePack（固定废 hex）/ Yh_sign（近名废值），全被动态覆盖；Java 层 Ak.FAKE_KEY=Fatdog_sore。
- **服务端**：POST /api/l34 验签 → Feistel 解密核对载荷与表单一致 → 返回 RC4 密文（SEED34=20271015，加和 49932）。server.py 内置 k34_feistel_dec 与 C 实现互为镜像。
- **三条官方路线**：① 纯 Frida：spawn 抢跑装钩子 → RegisterNatives 抓映射 → 偏移观察三联单 → 复刻三件套；② patch so：IDA 废掉扫描函数与 CRC 检查后重打包；③ unidbg：libl34.so 无 Java 回调依赖，补环境最省，离线批量签名。

## 关卡 35 设计明细（双匣暗渡：手写 3DES+SM4 + 干扰包，已落地）

- **App 端**：`k35Activity` ＋ `Ir`（三个 native 入口）＋ `Js`（每页三连包分发器：真包/错位包/废签包）。响应为明文 JSON，只有真包 nums 非空。
- **libl35.so**（由脚本生成，表格先过 NIST 已知向量自测）：文件前半四个无用变换函数（fake_b64_fold/dead_xor_mix/junk_pad/fake_round_mix，全部导出当噪音）；中段手写 SM4（S 盒 d690e9fe…、FK a3b1bac6…、CK 表）与 3DES（IP/E/P/S1-S8/PC1/PC2）；底部经函数指针表 K35_SM4_TBL/K35_DES_TBL 派发。
- **密钥派生**（不异或）：sm4_key=SHA256("Fatdog_sneak|sm4")[:16]；des_key=SHA256("Fatdog_sneak|3des")[:24]；master 即 Fatdog_sneak。标记以 UTF-16 存放（strings 默认盲）。
- **请求协议**：POST page/ts/e1/e2/sign；e1=hex(SM4(sm4_key,"page=N&ts=T"零填充))、e2=hex(3DES(des_key,大端ts 八字节))、sign=HMAC(master,e1+"|"+e2)。加密参数恰 2 个 + 动态 ts。
- **服务端**：POST /api/l35 用纯 Python sm4_decrypt + pycryptodome 拼 3DES 解密核对；近亲假钥 Fatdog_skulk 命中即 403，其余假包返回 nums:[] 形似而空。SEED35=20271111，加和 51217。
- **破解点**：① strings -el 拿 Fatdog_sneak → 派生双钥 → Python 复刻（SM4/DES3 服务端同款实现可参考）；② IDA 靠魔数定位两套算法 → 偏移 Hook k35_sm4_ecb/k35_des3_ecb 观察明文入参；③ 三连包甄别同 L31。陷阱：Kq.FAKE_KEY=Fatdog_skulk。

## 关卡 36 设计明细（查表识君：手写 AES-128 + Base64 藏钥，已落地）

- **App 端**：`l36Activity` ＋ `Mn`（nativeEnc/nativeSign）＋ `Nn`（GET /api/l36?page&ts&enc&sign）。响应明文 JSON。
- **libl36.so**：前半三个诱饵变换函数（fake_swap_pairs/fake_acc_mix/fake_rev，导出当噪音）；底部手写 **AES-128**（S 盒 637c777b…、Rcon、列主序 state、ShiftRows/MixColumns），经 K36_TBL[2] 指针表派发（volatile 槽位防折叠）。
- **Base64 藏钥**（不异或）：.rodata 明文躺着 24 字符 Base64 串 `tE5zEyf1b+fe49uJN4cY7w==`——运行时 b64decode 即得 16 字节 AES 钥匙；串本身是 SHA256("Fatdog_break|key")[:16] 的编码。mac=SHA256(Fatdog_break|"mac")。教学点：Base64 不是加密，但看着像乱码的串值得先试一手。
- **服务端**：`GET /api/l36` 验签+AES 解密核对载荷（pycryptodome AES-ECB）；近亲假钥 Fatdog_bluff 命中即 403。SEED36=20271125，加和 49495。
- **破解点**：① strings libl36.so 找 == 结尾的 24 字符串 → base64 解码 → Python 复刻 AES-ECB+HMAC 取数；② IDA 靠 S 盒魔数定位 k36_ecb → 偏移 Hook 观察明文入参。

## 关卡 37 设计明细（雪崩之谜：SHA-256 变体 IV + RC4 叠加，已落地）

- **App 端**：`m37Activity` ＋ `Qa`（nativeSign 单入口，静态注册）＋ `Rb`（GET /api/l37?page&ts&sign）。响应明文 JSON。
- **libl37.so**：手写 SHA-256 变体——K 表与压缩轮**与标准完全一致**（认骨架的依据），但初始 H[] 整组替换为 `SHA256("Fatdog_dodge|iv")`（标准 SHA 只用于派生 IV/RC4 钥匙，教科书常量不参与签名）；摘要出来再叠一层 `RC4(SHA256("Fatdog_dodge|rc4")[:16], dg)` 才是 sign。前半文件三个无用变换函数垫底，真身经 K37_TBL 派发。
- **服务端**：server.py 内置同一套纯 Python 变体实现（sha37_iv/rc4_37 与 C 互为镜像），`GET /api/l37` 重算比对。SEED37=20271223，加和 51242。样例对拍：variant_sign("page=1&ts=1787013761") = 902ac65869469750db3d5d70cbc89f1221a3a7ccc173ee85f38ff72a9cc53938。
- **破解点**：① strings -el 拿 Fatdog_dodge → Python 手写同款变体（IV 换血 + RC4 叠加两处改动点都要还原）；② 动态偏移 Hook k37_sha 后 dump 初始化完成的 h[]，一眼识破 IV 换血。陷阱：Sc.FAKE_KEY=Fatdog_drift；直接拿 hashlib 硬对永远失败。

## 实现清单（每关落地时已做）

1. `server.py` 加对应接口（验签/加解密/页面逻辑只在服务端，数字/flag 不进 APK）。
2. App 加关卡类（难读类名 + 工具类拆分 + 诱饵类），请求触发加密；网络地址统一由 `NetHost` 按环境选择。
3. `AndroidManifest.xml` / `MainActivity` / `strings.xml` / `view_levels.xml` / `DivineReflectionActivity`（神念自察功法名）/ `ProfileActivity`（境界）同步。
4. 重建 APK，抽查类与资源。
5. 更新 `README.md` / `SOLUTIONS.md` / `REPORT.md` / 本文件。

## 关卡 26 设计明细（双符合璧：双向 TLS / mTLS）

- **玩法（对玩家）**：服务端在 TLS 握手层强制验证客户端证书——没这张证书，抓包工具连握手都过不去。
- **App 端**：
  - `b26Activity`：关卡页（100 页×10 个分页取数求和，内置 `SUM_HASH` 校验，banner 用 `drawable-nodpi/level_26.jpg`）。
  - `Vd`：OkHttp 客户端。信任侧复用 `Tm.caDer()`；出示侧用 `Mc.loadP12()` → KeyManagerFactory 产出 KeyManager；签名密钥 = `Zt.pa()`(^0x3C) + `Vd.kb()`(^0x3C) = `fatdemo_mtls_key`；请求 `GET /api/mtls?page=N&ts=T&sign=…`，基址 `NetHost.mtlsBase()`（:8444）。
  - `Mc`：PKCS12 保险库。p12 密码 = `Zt.pxa()`(^0x37→`fatdemo_`) + `Mc.PXB`(^0x5B→`mt26`) = `fatdemo_mt26`；别名 `fatdog-client`；文件在 `assets/mt_client.p12`（由 `gen_certs.py` 生成并复制进 assets）。
  - `MtlsKit`：诱饵（假密码假别名，无人调用）。
- **服务端**：
  - `:8444` 跑**独立 FastAPI 实例** `mtls_app`——主 app（8787/8443）没有 `/api/mtls` 路由，杜绝跨端口绕过（404）。
  - uvicorn 参数：`ssl_cert_reqs=CERT_REQUIRED` + `ssl_ca_certs=certs/ca.crt`（客户端证书必须是内置 CA 签发的）。
  - SEED26=20270206，1000 个数字总和 50814。
- **破解点**：
  - 静态正解：解 XOR 得 HMAC 密钥与 p12 密码 → APK 里抠出 `mt_client.p12` → cryptography 导出证书私钥 → Python 带 CA+client 证书复刻 100 页取数（完整脚本见 SOLUTIONS 关卡 26）。
  - 动态正解：Frida 调 `Mc.buildPassword()` 倒密码，mitmproxy 挂 client 证书抓明文。
- **注意**：`gen_certs.py` 每次重跑会换掉 CA/server 证书——App 内嵌的 CA DER（Tm.CAA）、SPKI pin（Pn.PIN、Z24Core.PINX）必须同步重烘焙（本次已做）；后续如再生成证书记得同步这三处。

## 第三季规划（L28-37 · native 层系列）—— 已拍板，待落地

> 通过模式与 15-27 一脉相承：**数据只在服务端，通关 = 复刻/构造合法请求取满 100 页 → 加和提交 SUM_HASH 校验 → flag**。拿到密钥只是入场券（格式靠三联单观察 + 对拍确认）；L34 起"算不出算法"也有官方出路（Oracle/unidbg）。标记自 L28 启用 `Fatdog_<情绪词>`（情绪词恰好用满七关），L35 起进入动词系列。

### 总览

| 关卡 | 名称 | 核心考点 | 标记 | 难度 | 端点 | 状态 |
|---|---|---|---|---|---|---|
| 28 | 缄默之钥 | so 字符串加密，strings 失效 | Fatdog_unhappy | ★☆ | GET /api/l28 | 已落地（加和 49750） |
| 29 | 隐姓埋名 | 动态注册 RegisterNatives + 假导出陷阱 | Fatdog_angry | ★★ | GET /api/l29 | 已落地（加和 50208） |
| 30 | 无名剑冢 | strip 私有函数偏移 Hook + 诱饵函数（服务器当裁判） | Fatdog_gloomy | ★★★ | GET /api/l30 | 已落地（加和 51127） |
| 31 | 两界穿针 | 密钥跨层拼装（native 回调 Java，Java 半截进 R8 改名子包 q）＋干扰包 | Fatdog_lonely | ★★★★ | POST /api/l31 | 已落地（加和 50768） |
| 32 | 心魔哨兵 | 反检测四路哨兵 + 静默投毒；中招仅弹窗警告（不拉黑） | Fatdog_anxious | ★★★★ | GET /api/l32 | 已落地（加和 51745） |
| 33 | 金刚不坏 | .text CRC 自校验 + 记账守卫；三条解法全开 | Fatdog_jealous | ★★★★★ | GET /api/l33 | 已落地（加和 49502） |
| 34 | 万法归墟 | 综合卷：动态注册+无名 Feistel+反检测+CRC+响应加密；Frida / patch so / unidbg 三条官方路线 | Fatdog_grumpy | ★★★★★★ | POST /api/l34 | 已落地（加和 49932） |
| 35 | 双匣暗渡 | C 手写 3DES + SM4 常量识别＋干扰包 | Fatdog_sneak | ★★★★ | POST /api/l35 | 已落地（加和 51217） |
| 36 | 查表识君 | C 手写 AES，真身藏在无用方法底下 | Fatdog_break | ★★★ | GET /api/l36 | 规划 |
| 37 | 雪崩之谜 | C 手写 SHA-256 变体（改 IV/加盐），认骨架找改动点 | Fatdog_dodge | ★★★ | GET /api/l37 | 已落地（加和 51242） |

### 每关设计明细

**L28 缄默之钥**：密钥以 XOR 数组躺 `.rodata`，运行时解到栈缓冲喂 HMAC-SHA256——strings 一无所获。三条路：IDA 读解密循环 / 运行时 `Memory.scanSync` 搜明文 / 导出函数三联单拿返回值对拍。

**L29 隐姓埋名**：导出表只剩 `JNI_OnLoad`，真身经 `RegisterNatives` 运行时绑定；陷阱=导出 2 个假 `Java_com_..._sign`，能调但返回错值 → 服务器 403 教做人。正解：spawn 抢时机 + hook libart `RegisterNatives` 抓映射 → 偏移 Hook。

**L30 无名剑冢**：真签名在 strip 后无名的内部函数（noinline + 函数指针表间接调用模糊 xref），周围 3 个同形 HMAC 诱饵、密钥各异、输出都是合法 hex。正解：IDA 从入口跟调用链/常量 xref 锁定真身 → `base.add(offset)` Hook；真假只能靠服务器反馈验真。

**L31 两界穿针**：密钥前半 `Fatdog_` 在 Java（异或数组，放 R8 自动改名子包 `q`），后半 `lonely` 在 C；native 经 `FindClass → GetStaticMethodID → CallStaticObjectMethod` 回调取件、运行时拼整——单侧拿不全。加干扰包（见通用规格）：真包 `enc=hex(异或流(拼合密钥,payload))` + `sign=HMAC(拼合密钥,enc)` + 动态 ts，2 个加密参数。

**L32 心魔哨兵**：`JNI_OnLoad` 起守护线程四路检测：扫 `/proc/self/maps` 搜 frida 特征 / 试探 27042 等端口 / 枚举线程名 gum-js-loop·gmain·gdbus / clock 时间差。**中招不闪退：静默翻转密钥一字节，签名全错；App 确认污染后弹窗警告"环境异常"（教育向，仅警告，不拉黑不封号）**。静态复刻党全程免疫；动态党拆法三层：改名换端口 frida-server + strongR-frida 洗指纹 / IDA 定位检测函数偏移 Hook / hook `open`·`fgets` 给 maps 洗地。ptrace 占坑照放（讲清它防的是 gdb 不是 Frida）。

**L33 金刚不坏**：加载时对自身 `.text` 算 CRC32 存基线（校验器自身区间除外——该除外区间即 IDA 线索），每次签名重算比对；外加记账守卫（guardTicks/lastVerdict）防整体替换。**三解全开**：① hook `JNI_OnLoad` 于 onEnter 装完钩子——基线带钩建立永远一致；② 偏移 Hook 校验器（其区间被排除故安全）；③ Memory 找基线变量改写为当前实值。

**L34 万法归墟**：全家桶终卷：动态注册入口 + 真算法在无名函数（HMAC 前过一轮自定义 Feistel，纯猜必死）+ 四路反检测 + CRC 守卫 + 响应体 RC4 加密（C 实现）。**三条官方路线**：纯 Frida（拆检测→抓注册→偏移观察→复刻）/ patch so（IDA 改字节废守卫重打包）/ **unidbg（官方解法之一：so 拖进模拟环境当离线签名机，需补 Java 半截回调的 DvmObject 桩——为教程 23 铺路）**。

**L35 双匣暗渡**：单个 .c 文件手写 3DES 与 SM4 各一套，文件前半铺一堆无用变换函数（假 base64、死异或、废填充……），真加密压在文件底部且经函数指针表间接分发。考点=靠魔数认算法：DES 的 S1 盒 `14,4,13,1…` 与 PC1/PC2 表；SM4 的 S 盒 `d6 90 e9 fe…` 与 FK `a3b1bac6…`。干扰包：真包 `e1=hex(SM4(k1,"page=N&ts=T"))` + `e2=hex(3DES(k2,nonce))`，2 个加密参数 + 动态 ts；假包同形乱键。

**L36 查表识君**：手写 AES-128（加解密双向，响应体也要解）。同样一堆无用方法垫底、真身沉底间接调用。认 AES S 盒 `63 7c 77 7b…` 与 Rcon；密钥异或藏匿。找到轮密钥即可 Python 复刻。

**L37 雪崩之谜**：手写 SHA-256 但动了手脚（IV 换自定义值 / 末尾追加一轮自定义盐压缩）——K 表完好可认出骨架，标准库对不上就是要找的改动点；Python 复刻同一变体验收。

### 干扰包通用规格（落在 L31 / L35）

- 每次取一页，客户端连发 3-5 个请求：1 真 + 2-4 假；真假同形（字段名一致），假包密钥错误或载荷为噪声。
- 服务端行为：真包返回 `{"page":N,"nums":[...]}`；假包返回 HTTP 200 + `{"page":N,"nums":[]}`（形似而空），部分假包返回 403——逼玩家靠响应内容而非状态码分辨。
- 加密参数数量硬性约束：**≥2 且 ≤3**；必须含动态值 ts（600s 窗口，防重放）。
- 玩家识别手段分级：Hook OkHttp 响应回调看哪包有货（易）/ mitmproxy 对比流量（中）/ 纯静态读发包代码（难）。

### 工程与文档注意

- **so 分库防剧透**：每关独立 `libl28.so` ~ `libl37.so`，绝不并入 L25 的 libnative.so（否则打 L25 解包即看到后续答案）。
- 类续谱：活动类 d28/e29/f30/g31/h32/i33/j34/k35/l36/m37 Activity；工具类两字母新组合；L31 的 Java 半截进自动改名子包 `q`。
- 服务端全部挂 8443 主 app 新路由；SEED/加和实现时记录回填总览表与落地总表。
- flag 格式不变 `FLAG_18_Lxx{...}`（本季只换密钥标记）。
- 文档同步按 SKILL Checklist：README 关卡行+分级提示折叠块、SOLUTIONS 双路线题解（L34 含 unidbg 路线）、PLANNED 状态回填。
- 教程联动：本季配套教程 22《Frida Hook 实战 Native 层》（已发）；L34 unidbg 路线为教程 23 预留靶场。

### 决策记录（已拍板）

- L34 unidbg 列为官方解法之一；
- L32 中招只弹窗警告，不做 IP 拉黑；
- L33 三条解法全部开放；
- 干扰包落在 L31、L35 两关（前者练响应甄别，后者天然双算法凑满加密参数配额）。

## 后续规划

- **昆仑山秘境（已启用）**：KL 独立编号五连关，纯本地提交模式；入口双通道（通关 37 关或密令）。KL1 山门已落地（xorshift32+libkunlun1.so），KL2-KL5 规划见对话记录与 00-路线图。

- 第三季：native 层系列 L28-37，完整规划见上文《第三季规划》章节，逐关落地后回填状态与加和。
- **标记命名切换（L28 起生效）**：密钥/口令等标记弃用 `fatdemo_` 前缀，改用 `Fatdog_<后缀>`——后缀先用情绪词（unhappy/angry/gloomy…），情绪词用尽换动词（sneak/break/dodge…）；详细规则与选词表见 `SKILL.md` §四。L1-27 维持 `fatdemo_` 不动。
- 可选加料：签名校验防重打包、root/模拟器检测、flag 全部改服务端下发。
