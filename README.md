# FatdogReverse

**Android 逆向工程实战靶场 · 109 关 · 本地离线 · 答案可复现**

![Platform](https://img.shields.io/badge/Platform-Android%205%2B-3DDC84)
![Levels](https://img.shields.io/badge/Levels-109-blue)
![Build](https://img.shields.io/badge/Build-No%20Gradle-orange)
![Server](https://img.shields.io/badge/Server-FastAPI-009688)
![Tools](https://img.shields.io/badge/Tools-Frida%20%7C%20jadx%20%7C%20IDA%20%7C%20apktool-lightgrey)

FatdogReverse 是一套**完全离线运行**的 Android 逆向工程练习靶场。它以「闯关」的形式把 Java/DEX 静态分析、Smali 篡改、Frida、Xposed、网络协议还原、密码学、HTTPS/mTLS、Native 逆向、反调试、代码完整性校验、脱壳、VMP 与签名校验对抗串联成一条渐进路线。

设计上有一条核心原则：**所有关卡数据、密钥与校验逻辑都只存在于本地 `server.py`，APK 里没有**。因此每一关都能在 `APK + 本项目` 范围内完整复现，不依赖任何在线服务，也不需要真实 App 样本。

> 本项目仅用于本地学习、研究与已授权设备上的安全测试。

---

## 目录

- [项目特色](#项目特色)
- [关卡总览](#关卡总览)
- [快速开始](#快速开始)
- [抓包环境配置](#抓包环境配置)
- [项目结构](#项目结构)
- [通关机制](#通关机制)
- [剧透文件说明](#剧透文件说明)
- [常见问题](#常见问题)
- [免责声明与使用许可](#免责声明与使用许可)

---

## 项目特色

**数据完全在后端。** 数字、密钥、部分 flag 只由 `server.py` 生成，APK 中不存在。网络关必须启动服务端才能取数，且服务端会校验签名、时间窗与防篡改状态。

**离线可复现。** 全套关卡不连外网。服务端使用自签 CA，证书、密钥、种子全部随仓库提供，`python server.py` 一跑就能复现整条链路。

**覆盖完整攻防链路。** 从「字符串里的明文 flag」一路到「OLLVM 控制流平坦化 + 魔改算法 + 加固壳脱壳」，难度按星级递进，适合系统化练习而不是零散做题。

**防作弊设计贯穿始终。** 大量关卡埋有**一字之差的诱饵密钥**、**同形函数副本**、**假 pin**、**投毒机制**（检测到 Hook/篡改后静默翻转一个字节，签名全错而不给任何提示）。照抄代码里的字符串通常得不到正确答案。

**每题多解且可验证。** 大部分关卡同时支持「静态复刻」与「动态 Hook」两条主线，题解里给出完整 Python 复刻脚本与逐字节对拍样例，做完能自己验证对错。

**构建不依赖 Android Studio。** 一个 `build_apk.py` 直接调用 `aapt2` / `d8` / `zipalign` / `apksigner`，几分钟出包。

---

## 关卡总览

当前共 **109 关**，分为主流程与天地秘境两大块。

| 编号 | 数量 | 内容 |
|---|---:|---|
| `L1-L53` | 53 关 | 主流程，按大厅分类推进 |
| `KL1-KL55` | 50 关 | 天地秘境（`KL31-KL35` 规划中，暂未开放） |
| `KKL1-KKL5` | 5 关 | 太玄之初追加卷（C++ 壳零件与 VMP 签名链） |
| **合计** | **109 关** | |

### 主流程 `L1-L53`

| 分类 | 关卡 | 数量 | 主要内容 |
|---|---|---:|---|
| 静态分析 | `L1-L6` | 6 | 明文、编码、字符串还原、摘要、资源文件、隐藏 Activity |
| Smali 挑战 | `L7-L9`、`L20` | 4 | Smali 跳转与数组、逻辑链、复杂状态机、重打包改开关 |
| Frida Hook（Java 层） | `L10-L14` | 5 | `MessageDigest`、`Mac`、`Cipher`、多层变换、诱饵类 |
| 网络对抗 | `L15-L19` | 5 | HMAC 签名、RC4、国密 SM4/SM3、RSA/DES、AES + R8 混淆 |
| SSL 抓包 | `L21-L27` | 7 | TrustManager、CertificatePinner、WebView 证书错误、反 Hook 守卫、JNI 门禁、mTLS |
| Native 试炼 | `L28-L37`、`L37b` | 11 | 字符串加密、动态注册、指针派发、跨层调用、反调试、CRC 自校验、魔改 MD5 |
| Xposed 实战 | `L38-L42` | 5 | Hook 返回值、篡改入参、读取私有字段、替换方法体、持久化验证 |
| 签名校验对抗 | `L43-L47` | 5 | SigningInfo、Native 摘要下沉、APK 自解析、证书派生密钥、综合收官 |
| Native大陆 | `L48-L53` | 6 | C++ name mangling、STL 容器、vtable、模板、异常控制流、魔改算法 |

> 其中 `L6` 没有入口按钮，藏在 `AndroidManifest.xml` 里，需要自己找。

### 天地秘境 `KL1-KL55` / `KKL1-KKL5`

完成全部主流程关卡后解锁；也可以在门禁处输入密令 `Fatdog` 直接进入。

| 分区 | 关卡 | 数量 | 主要内容 |
|---|---|---:|---|
| 昆仑山 | `KL1-KL5` | 5 | Native 基础、动态注册、Java 回调、反模拟器、综合入口 |
| 流沙河 | `KL6-KL10` | 5 | 魔改 AES / DES / SM4 / RC4 / SHA-256 五连关 |
| 幽冥海 | `KL11-KL15` | 5 | SO Patch 对抗：静态 patch、动态 patch、反 patch、多 SO 交叉验证 |
| 太玄之初 | `KL16-KL20` | 5 | 加固壳分代脱壳：一代壳、二代壳（类抽取 / 方法抽取）、三代壳 |
| 太玄之初追加卷 | `KKL1-KKL5` | 5 | C++ 壳零件、DEX 内存加载、反检测、CRC、VMP 签名链 |
| 扶桑树 | `KL21-KL28` | 8 | Frida 检测与反检测：端口、fd、maps、auxv、ptrace、时序 |
| 天机阁 | `KL29-KL30` | 2 | 自定义 TLV 与 Protobuf 二进制协议逆向 |
| 碧落天 | `KL36-KL40` | 5 | Flutter/Dart 真机逆向：AOT 快照（Blutter）、混淆对抗、BoringSSL pinning、`dart:ffi` |
| 须弥界 | `KL41-KL45` | 5 | H5/WebView 逆向：JSBridge、资源加密、JS 层加密还原、协议重放 |
| 九幽 | `KL46-KL50` | 5 | Root 检测与绕过：环境完整性、bootloader、mount namespace、Play Integrity 仿真 |
| 迷阵 | `KL51-KL55` | 5 | OLLVM 混淆对抗：控制流平坦化、虚假控制流、字符串加密、间接跳转、魔改算法 |

> `KL31-KL35`（天机阁扩展：gRPC / GraphQL 协议）尚在规划中，未计入当前关卡数。

---

## 快速开始

### 环境要求

| 组件 | 版本 |
|---|---|
| JDK | 17 或更高 |
| Android SDK | Platform 34 + Build Tools 34.0.0 |
| NDK | 26.1.10909125（部分 Native 关卡需要） |
| Python | 3.9+ |

解题时按需准备：`jadx`、`apktool`、`frida` / `frida-server`、Xposed 或 LSPosed、`mitmproxy`、Charles Proxy、IDA / Ghidra / unidbg。

### 第一步：启动服务端

```bash
python -m pip install fastapi uvicorn python-multipart pycryptodome cryptography
```

如果 `certs/` 不存在（首次克隆后常见），先生成 TLS 与 mTLS 证书：

```bash
python gen_certs.py
```

启动：

```bash
python server.py
```

服务端会监听三个端口，并在启动日志里打印各关的种子与数据校验值。

### 第二步：构建 APK

```bash
python build_apk.py
```

产物为根目录下的 `FatdogReverse.apk`。构建脚本会自动探测本机 SDK / JDK / NDK 路径，无需手工配置环境变量。

### 第三步：安装

```bash
adb install -r FatdogReverse.apk
```

> 如果设备上已安装过使用不同签名的旧版本，需要先卸载；**卸载会清除本地通关进度**。

### 第四步：让 App 连上服务端

模拟器会自动通过 `10.0.2.2` 访问宿主机，无需额外配置。

真机的 `127.0.0.1` 指向手机自身，需要把电脑端口反向映射到手机：

```bash
adb reverse tcp:8787 tcp:8787
adb reverse tcp:8443 tcp:8443
adb reverse tcp:8444 tcp:8444

adb reverse --list    # 确认映射生效
```

端口映射在拔掉 USB、重启手机、重启 ADB 或重启电脑后失效，需要重新执行。

也可以把 `app/assets/config.json` 里的 `api_base_url` 改成电脑的局域网地址，让手机通过同一 Wi-Fi 直连（需放行防火墙对应端口）。

---

## 抓包环境配置

<details>
<summary>点击展开：端口拓扑、证书分工与 Charles 配置步骤</summary>

### 端口与协议

| 端口 | 协议 | 适用关卡 |
|---|---|---|
| `8787` | HTTP | `L15-L19`、`KKL2-KKL5` |
| `8443` | HTTPS | `L21-L25`、`L27-L37`、`L37b`、`L43-L53`、`KL6-KL10`、`KL30` |
| `8444` | HTTPS + mTLS | `L26` |

App 的地址选择逻辑位于 `NetHost.java`：`httpBase()` → `8787`，`httpsBase()` → `8443`，`mtlsBase()` → `8444`。

### 证书分工

| 文件 | 用途 |
|---|---|
| `certs/ca.crt` / `certs/ca.key` | 项目自签 CA。`8443` 的多数客户端把它内嵌进 App，只信任它签发的证书 |
| `certs/server.crt` / `certs/server.key` | 本地服务端证书，由项目 CA 签发，SAN 覆盖 `localhost`、`127.0.0.1`、`10.0.2.2` |
| `certs/client.crt` / `certs/client.key` / `certs/client.p12` | `L26` 的客户端证书，PKCS#12 密码 `fatdemo_mt26`；同一文件会复制为 `app/assets/mt_client.p12` 打入 APK |

**注意：证书与 APK 必须匹配。** 重新运行 `python gen_certs.py` 后，必须同时重新构建并安装 APK，否则服务端换了新 CA、App 内仍是旧 CA，HTTPS 关卡会握手失败。

另外，APK 内只嵌入了 CA **公钥**（`Tm.CAA`，异或 `0x5A`），不含 `ca.key`。只拿到 APK 时可以还原出 `ca.crt`，但无法用它给抓包工具签发叶证书。

### 真机 Charles 抓包

App 固定访问 `127.0.0.1`，推荐使用 Charles 的 **Reverse Proxies**（反问代理），而不是给手机配正向代理。

| App 请求 | `adb reverse` | Charles 本地端口 | Charles 上游 |
|---|---:|---:|---|
| `http://127.0.0.1:8787` | `tcp:8787 tcp:18787` | `18787` | `127.0.0.1:8787` |
| `https://127.0.0.1:8443` | `tcp:8443 tcp:18443` | `18443` | `127.0.0.1:8443` |
| `https://127.0.0.1:8444` | `tcp:8444 tcp:18444` | `18444` | `127.0.0.1:8444` |

配置步骤：

1. 启动 `python server.py`，服务端仅作为 Charles 的上游。
2. `Proxy -> Reverse Proxies` 添加上述三条映射并启用。
3. `Proxy -> Start SSL Proxying`，在 `SSL Proxying Settings` 中允许 `127.0.0.1:8443`、`127.0.0.1:8444`。
4. **开卷捷径**：在 `SSL Proxying Settings -> Root Certificate` 导入 `certs/ca.crt` 与 `certs/ca.key`，让 Charles 用项目 CA 给 `127.0.0.1` 换发叶证书。这一步只解决抓包环境，**不能替代题解里的 Hook 主线**。
5. `Client Certificates` 中添加 `127.0.0.1:8444`，导入 `certs/client.p12`，密码 `fatdemo_mt26`，启用（仅 `L26` 需要）。
6. 先清理旧映射，再建立抓包映射：

```bash
adb reverse --remove-all

adb reverse tcp:8787 tcp:18787
adb reverse tcp:8443 tcp:18443
adb reverse tcp:8444 tcp:18444
```

7. 进入网络关，Charles 记录中应能看到对应端口的请求。

### 常见误区

- 只把 Charles 自己的根证书装到手机上，**不能**解决 App 的 `CertificatePinner`，也不一定能解决只信任内嵌项目 CA 的 `TrustManager`。
- `L22`、`L24`、`L27` 叠加了 **SPKI pin**。代理叶证书的公钥与原服务端证书不同，必须按题解做换 pin 或绕过 pin 校验。
- `L23` 是 WebView 的证书错误分支，导入项目 CA **不能**替代关卡要求的 `onReceivedSslError -> handler.proceed()`。
- `L15-L19` 是纯 HTTP，不需要导入任何 CA。

> `L21-L27` 的官方解题主线是通过 Frida 绕过 App 自身的 TLS 校验。直接导入仓库提供的 `ca.crt` / `ca.key` 属于**开卷捷径**，不代表 APK-only 或真实环境下的思路。

</details>

---

## 项目结构

```text
FatdogReverse/
├── app/
│   ├── assets/                  # 配置、壳 payload、加密 DEX、mTLS 客户端证书
│   ├── jni/                     # Native 关卡源码与 Android.mk
│   ├── res/                     # 布局、图片、字符串资源
│   └── src/com/fatdog/reverse/  # Java 关卡源码
├── certs/                       # 本地 TLS / mTLS 证书（由 gen_certs.py 生成）
├── keystore/                    # APK 签名密钥
├── libs/                        # OkHttp、Okio、Kotlin 等第三方依赖
├── tools/                       # 打包与辅助脚本
├── build_apk.py                 # 一键构建 APK
├── gen_certs.py                 # 生成 CA、服务端与客户端证书
├── server.py                    # 本地网络关卡服务端
├── SOLUTIONS.md                 # 完整题解（剧透）
└── README.md                    # 项目说明
```

构建相关的日志文件（`comp_out.txt`、`error/`）与构建产物（`build/`、`app/obj/`、`FatdogReverse.apk`）都不入库。

---

## 通关机制

1. 每关都有独立的输入框、交互或网络协议，目标是通过真实分析得到结果，或让检测链路正确通过。
2. **检测类按钮只展示状态，不会直接增加通关数**。反调试、CRC 自校验、记账守卫、签名校验类关卡需要真正处理对应链路。
3. 网络关的数据由本地服务端生成，**必须启动服务端**才能取数。多页取数关卡需要取满全部页面并提交最终计算结果。
4. 通关后 `PassLog` 记录关卡编号，个人主页的境界与进度同步更新。
5. 卸载 App、更换签名、清除应用数据或重新打包覆盖安装，都可能丢失本地进度。
6. 进度丢失时，可在个人主页「前世今生」页面输入密令 `Fatdog` 手动补回或撤销记录。
7. **标准练习方式：只分析 `FatdogReverse.apk`。** 直接阅读本仓库源码会看到实现细节与部分答案。

---

## 剧透文件说明

| 文件 / 目录 | 用途 | 是否剧透 |
|---|---|---|
| `SOLUTIONS.md` | 全部关卡的题解、flag、服务端取数结果、Python 复刻脚本与 Frida 思路 | 是 |
| `server.py` | 网络关协议、密钥、种子与服务端数据生成逻辑 | 是 |
| `app/src/` | App 的 Java 源码，包含关卡逻辑与校验链 | 是 |
| `app/jni/` | 各关 C/C++ 源码、自定义算法与 Native 校验实现 | 是 |
| `app/assets/` | 配置、壳 payload、加密 DEX、mTLS 客户端证书 | 部分关卡是 |
| `FatdogReverse.apk` | 构建后的实际靶场 APK | 否 |

准备自己练习的同学，建议只读本文档的安装与启动部分，先不要打开 `SOLUTIONS.md`、`server.py`、`app/src/` 与 `app/jni/`。

---

## 常见问题

<details>
<summary>网络关拿不到数字怎么办？</summary>

按顺序排查：

1. `python server.py` 是否正在运行。
2. 真机是否执行了对应端口的 `adb reverse`。
3. `adb reverse --list` 能否看到端口映射。
4. 服务端是否打印出对应请求日志。
5. 返回 `403` 时，检查签名、密钥、时间戳与防篡改状态。
6. `8443` 关卡需要处理自签证书或证书锁定。
7. `8444` 关卡必须携带 APK 内置的 mTLS 客户端证书。

</details>

<details>
<summary>安装时提示签名不一致？</summary>

说明设备上的 APK 与待安装 APK 使用了不同签名。只能卸载旧版本后安装，或用与旧版本相同的签名重新构建。**卸载会清除应用本地数据，包括通关进度。**

</details>

<details>
<summary>重新打包后关卡行为异常？</summary>

部分关卡会校验 APK 签名、代码段 CRC、Native 指令或响应签名。重新打包、修改 Smali、Patch SO 或 Hook 校验器后，关卡可能主动失败或静默返回错误——**这属于靶场逻辑的一部分**，不是 bug。

</details>

<details>
<summary>克隆后构建失败，提示缺少 jar？</summary>

第三方依赖（OkHttp、Okio、Kotlin、annotations）位于 `libs/`，该目录默认不入库。请按项目开发手册中的白名单把这些 jar 放入 `libs/` 后再执行 `python build_apk.py`。

</details>

<details>
<summary>克隆后 HTTPS 关卡握手失败？</summary>

`certs/` 目录默认不入库。先执行 `python gen_certs.py` 生成证书，再重新构建 APK（保证 App 内嵌的 CA 与服务端一致）。

</details>

---

## 免责声明与使用许可

本项目是一个**教学性质的逆向工程靶场**，所有关卡、服务端与算法均为自研，不包含任何真实第三方 App 的代码、数据或证书。

- 请在**自己的设备**或**已获授权的设备**上练习。
- 请勿将本项目的任何技术手段用于未授权的目标。
- 项目以「学习与研究」为目的提供，不构成任何形式的担保。

如果这些关卡帮你搞懂了某个知识点，欢迎提 Issue 交流；发现题目本身有 bug，也欢迎反馈。
