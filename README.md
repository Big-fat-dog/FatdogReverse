# FatdogReverse

FatdogReverse 是一个面向 Android 逆向工程练习的本地靶场。

项目包含 Java/DEX 静态分析、Smali 修改、Frida、Xposed、网络协议、密码学、HTTPS/mTLS、Native、反调试、代码完整性校验、脱壳、VMP 和签名校验对抗等内容。除本地 `server.py` 外不依赖在线服务，关卡数据、密钥和校验逻辑都可以在当前项目中完整复现。

> 仅用于本地学习、研究和已授权设备。

## 内容概览

当前共包含：

| 编号 | 数量 | 内容 |
|---|---:|---|
| `L1-L53` | 53 关 | 基本关卡 |
| `KL1-KL30` | 30 关 | 天地秘境 |
| `KKL1-KKL5` | 5 关 | 太玄之初独立壳系列 |
| 合计 | 88 关 | Java、Native、网络与壳对抗 |

主要能力覆盖：

- APK、DEX、资源、Manifest 与 Smali 静态分析
- Frida Hook Java 层与 Native 层
- Xposed 模块、参数篡改、字段读取和方法替换
- HMAC、AES、RC4、RSA、DES/3DES、SM3、SM4 和自定义算法
- HTTP、HTTPS、证书锁定、WebView 证书校验和 mTLS
- JNI、动态注册、字符串加密、函数指针派发和多 SO 交叉调用
- 反调试、反 Frida、CRC 自校验和记账守卫
- DEX 静态加密、热加载、OLLVM、VMP 与 DEX 抽取还原
- APK 签名校验和证书派生密钥

## 基本关卡

| 分类 | 关卡 | 主要内容 |
|---|---|---|
| 静态分析 | `L1-L6` | 明文、编码、字符串还原、摘要、资源文件和隐藏 Activity |
| Smali 挑战 | `L7-L9`、`L20` | Smali 跳转、数组、逻辑链、重打包和复杂状态机 |
| Frida Hook（Java 层） | `L10-L14` | `MessageDigest`、`Mac`、`Cipher`、多层变换和诱饵类 |
| 网络对抗 | `L15-L19` | HMAC 签名、RC4、国密、RSA/DES、AES 和 R8 混淆 |
| SSL 抓包 | `L21-L27` | TrustManager、CertificatePinner、WebView、反 Hook、JNI 和 mTLS |
| Native 试炼 | `L28-L37` | 字符串加密、动态注册、指针派发、跨层调用、反调试和自校验 |
| Xposed 实战 | `L38-L42` | Hook 返回值、篡改参数、读取字段、替换方法和持久化 |
| 签名校验对抗 | `L43-L47` | SigningInfo、Native 摘要、APK 自解析和证书派生密钥 |
| Native大陆 | `L48-L53` | C++ name mangling、STL、vtable、模板、异常和魔改算法综合关 |

部分网络关采用分页取数模式，需要取得服务端返回的全部数据并提交最终计算结果。数据只存在于本地服务端，不包含在 APK 资源中。

## 天地秘境

天地秘境需要完成全部 40 个基本关卡后进入，也可以在门禁处输入密令 `Fatdog` 进入。

| 分区 | 关卡 | 主要内容 |
|---|---|---|
| 昆仑山 | `KL1-KL5` | Native 基础、动态注册、Java 回调、反模拟和综合入口 |
| 流沙河 | `KL6-KL10` | 魔改 AES、DES、SM4、RC4、SHA-256 与复合算法 |
| 幽冥海 | `KL11-KL15` | 字符串偏移、魔改哈希、CRC 自校验、多 SO 交叉调用和递进谜题 |
| 太玄之初 | `KL16-KL20` | 一代壳、二代壳、OLLVM、VMP 和三代壳综合 |
| 太玄之初追加卷 | `KKL1-KKL5` | C++ 壳零件、DEX 内存加载、反检测、CRC 和 VMP 签名链 |
| 扶桑树 | `KL21-KL28` | 端口、fd、maps、auxv、ptrace、时序和反调试组合检测 |
| 天机阁 | `KL29-KL30` | 自定义 TLV 与 Protobuf 二进制协议 |

## 通关规则

1. 每个关卡都有独立的输入、交互或网络协议，目标是通过真实分析得到结果或让检测链路正确通过。
2. 检测类按钮只展示当前状态，不会直接增加通关数。反调试、CRC、记账和签名校验关卡需要实际处理对应链路。
3. 网络关卡的数据由本地服务端生成，必须启动服务端后才能取数。
4. 通关后，`PassLog` 会记录关卡编号，个人主页的境界和进度会同步更新。
5. 卸载 App、更换签名、清除应用数据或重新打包后覆盖安装，可能丢失本地进度。
6. 如果进度丢失，可在个人主页的“前世今生”页面输入密令 `Fatdog`，手动补回或撤销关卡记录。
7. 标准练习方式是只分析 `FatdogReverse.apk`。直接查看本仓库源码会看到实现细节和部分答案。

## 解题答案与剧透文件

| 文件或目录 | 用途 | 是否剧透 |
|---|---|---|
| `SOLUTIONS.md` | 全部关卡的题解、flag、服务端取数结果、Python 复刻脚本和 Frida 思路 | 是 |
| `server.py` | 网络关协议、密钥、种子和服务端数据生成逻辑 | 是 |
| `app/src/` | App 的 Java 源码，包含关卡逻辑和部分校验链 | 是 |
| `app/jni/` | 各关 C/C++ 源码、自定义算法和 Native 校验实现 | 是 |
| `app/assets/` | 配置、壳 payload、加密 DEX 和 mTLS 客户端证书 | 部分关卡是 |
| `FatdogReverse.apk` | 构建后的实际靶场 APK | 否 |

如果准备自己练习，建议只阅读 README 的安装和启动部分，不要打开 `SOLUTIONS.md`、`server.py`、`app/src/` 和 `app/jni/`。

## 网络关卡配置与抓包

服务端共监听三个端口：

HTTP 关卡不使用 TLS；HTTPS 与 mTLS 关卡使用 `certs/ca.crt` 对应的项目自签 CA。

> `L21-L27` 的题解主线是通过 Frida Hook/绕过 App 的 TLS 校验。直接导入仓库提供的 `certs/ca.crt` 和 `certs/ca.key`，让 Charles 冒充项目 CA 签发叶证书，只适用于当前开卷实验室，属于抓包捷径，不代表 APK-only 或真实环境下的解题思路。`L26` 是例外：它必须在握手层提取并使用 APK 内的客户端证书，但仅导入服务端 CA 仍不足。

| 端口 | 协议 | 适用关卡 |
|---|---|---|
| `8787` | HTTP | `L15-L19`、`KKL2-KKL5` |
| `8443` | HTTPS | `L21-L25`、`L27-L37`、`L43-L53`、`KL6-KL10`、`KL30` |
| `8444` | HTTPS + mTLS | `L26` |

证书分工如下：

- `certs/ca.crt` / `certs/ca.key`：项目 CA。`8443` 的大部分 TLS 客户端把这张 CA 编进 App，只信它签发的证书。
- `certs/server.crt` / `certs/server.key`：本地服务端证书，由项目 CA 签发，SAN 覆盖 `localhost`、`127.0.0.1` 和 `10.0.2.2`。
- `certs/client.crt` / `certs/client.key` / `certs/client.p12`：`L26` 的客户端证书。PKCS#12 密码为 `fatdemo_mt26`，同一文件也会复制到 `app/assets/mt_client.p12` 并打入 APK。

`certs/ca.crt` 与 `certs/ca.key` 必须和当前安装的 APK 匹配。重新运行 `python gen_certs.py` 后，应同时重新构建并安装 APK；否则服务端换成了新 CA，App 内仍是旧 CA，HTTPS 关卡会握手失败。

注意：APK 内只嵌入了 CA 公钥（`Tm.CAA`，异或 `0x5A`），并不包含 `certs/ca.key`。只拿到 APK 时可以还原 `ca.crt`，但无法用这张 CA 给 Charles 签发叶证书；这时要么用服务端仓库中匹配的 `ca.key`，要么走 Frida 绕过 TrustManager（以及关卡自己的 pin 校验）。

安装服务端依赖：

```bash
python -m pip install fastapi uvicorn python-multipart pycryptodome cryptography
```

如果 `certs/` 不存在，先生成 HTTPS 与 mTLS 证书：

```bash
python gen_certs.py
```

启动服务端：

```bash
python server.py
```

### 模拟器直连

模拟器会自动使用 `10.0.2.2` 访问宿主机，不需要执行 `adb reverse`。

### 真机直连

真机的 `127.0.0.1` 指向手机自身，因此需要通过 ADB 将电脑端口映射到手机：

只解题、不抓包时，把服务端三个端口直接映射到真机的同名端口：

```bash
adb reverse tcp:8787 tcp:8787
adb reverse tcp:8443 tcp:8443
adb reverse tcp:8444 tcp:8444
```

确认映射：

```bash
adb reverse --list
```

端口映射会在拔掉 USB、重启手机、重启 ADB 或重启电脑后失效，需要重新执行。三个映射可以同时存在。

### 真机 Charles 抓包

App 在真机上固定访问 `127.0.0.1`。要让 Charles 同时看到请求和上游 TLS，推荐使用 Charles Reverse Proxies，而不是给小黄鸟或手机 Wi-Fi 配普通正向代理。

拓扑如下：

| App 请求 | `adb reverse` | Charles 本地端口 | Charles 上游 |
|---|---:|---:|---|
| `http://127.0.0.1:8787` | `tcp:8787 tcp:18787` | `18787` | `127.0.0.1:8787` |
| `https://127.0.0.1:8443` | `tcp:8443 tcp:18443` | `18443` | `127.0.0.1:8443` |
| `https://127.0.0.1:8444` | `tcp:8444 tcp:18444` | `18444` | `127.0.0.1:8444` |

配置步骤：

1. 启动 `python server.py`，保持服务端只作为 Charles 的上游。
2. 打开 Charles 的 `Proxy -> Reverse Proxies`，分别添加三条映射并勾选启用总开关：
   - `18787 -> 127.0.0.1:8787`
   - `18443 -> 127.0.0.1:8443`
   - `18444 -> 127.0.0.1:8444`
3. 执行 `Proxy -> Start SSL Proxying`，并在 `Proxy -> SSL Proxying Settings` 中允许 `127.0.0.1:8443`、`127.0.0.1:8444`（也可用 `*:*` 临时调试）。
4. **开卷捷径**：在 `SSL Proxying Settings -> Root Certificate` 导入 `certs/ca.crt` 与 `certs/ca.key`。这样 Charles 会用项目 CA 给 `127.0.0.1` 换发叶证书。该步骤只解决抓包环境，不替代 `SOLUTIONS.md` 中的 Hook 题解主线。
5. 在 `Client Certificates` 中添加 `127.0.0.1:8444`，导入 `certs/client.p12`（或 `app/assets/mt_client.p12`），密码 `fatdemo_mt26`，并设为 Enabled。该项只服务于 `L26` 的 mTLS。
6. 在电脑上建立反向映射：

先移除真机直连时建立的同名映射（`adb reverse --remove tcp:8787` 等，或 `adb reverse --remove-all`），再执行：

```bash
adb reverse tcp:8787 tcp:18787
adb reverse tcp:8443 tcp:18443
adb reverse tcp:8444 tcp:18444

adb reverse --list
```

7. 从 App 进入网络关；Charles 的 Reverse Proxy 记录中应能看到对应端口的请求。

注意事项：

- 只把 Charles 自己的根证书装到手机上，不能解决 App 的 `CertificatePinner`，也不一定能解决只信任内嵌项目 CA 的 `TrustManager`。若走当前仓库的开卷捷径，抓 `8443` 时应让 Charles 使用项目 CA 作为签发根证书；题解主线仍按 `SOLUTIONS.md` 做 Hook。
- `L22`、`L24`、`L27` 还有 SPKI pin。Charles 叶证书与本地服务端证书的公钥不同，必须按 `SOLUTIONS.md` 中的 Frida 方案换 pin 或绕过 pin 校验。
- `L23` 是 WebView 的 SSL 错误分支。导入项目 CA 不能替代关卡要求的 `onReceivedSslError -> handler.proceed()` 处理。
- `L15-L19` 是纯 HTTP，不需要导入任何 CA。反向代理建立后即可直接查看请求和响应。

App 的地址选择逻辑位于 `NetHost.java`：

- `NetHost.httpBase()` 使用 `8787`
- `NetHost.httpsBase()` 使用 `8443`
- `NetHost.mtlsBase()` 使用 `8444`
- `app/assets/config.json` 的 `api_base_url` 默认为 `AUTO`

也可以将 `api_base_url` 改成电脑的局域网地址，让手机通过同一 Wi-Fi 访问。该方式需要手机和电脑处于同一网络，并允许本机防火墙放行对应端口。

## 构建

构建不依赖 Android Studio 或 Gradle。

需要：

- JDK 17 或更高版本
- Android SDK Platform 34
- Android Build Tools 34.0.0
- NDK 26.1.10909125
- Python 3

构建：

```bash
python build_apk.py
```

输出文件：

```text
FatdogReverse.apk
```

安装：

```bash
adb install -r FatdogReverse.apk
```

如果设备中已经安装的 APK 使用了不同签名，需要先卸载旧版本，但卸载会清除本地通关进度。

部分关卡会另外使用以下工具，是否安装取决于准备练习的关卡和所选解法：

- `jadx`
- `apktool`
- `frida` / `frida-server`
- Xposed 或 LSPosed
- `mitmproxy`
- Charles Proxy（Windows/macOS 均可）
- IDA、Ghidra 或 unidbg

## 项目结构

```text
FatdogReverse/
├── app/
│   ├── assets/                 # 配置、壳 payload、加密 DEX、mTLS 证书
│   ├── jni/                    # Native 关卡源码与 Android.mk
│   ├── res/                    # 布局、图片、字符串等资源
│   └── src/com/fatdog/reverse/ # Java 关卡源码
├── certs/                      # 本地 TLS 与 mTLS 证书
├── keystore/                   # APK 签名密钥
├── libs/                       # OkHttp、Okio、Kotlin 等依赖
├── tools/                      # 打包与 Smali 工具
├── build_apk.py                # 一键构建 APK
├── gen_certs.py                # 生成服务端、CA 和客户端证书
├── server.py                   # 本地网络关卡服务端
├── SOLUTIONS.md                # 完整题解
└── README.md                   # 项目说明
```

## 常见问题

### 网络关没有数字

按顺序检查：

1. `python server.py` 是否正在运行。
2. 真机是否执行了对应端口的 `adb reverse`。
3. `adb reverse --list` 是否能看见端口映射。
4. 服务端是否出现对应请求日志。
5. 返回 `403` 时检查签名、密钥、时间戳和反篡改状态。
6. `8443` 关卡需要处理自签证书或证书锁定。
7. `8444` 关卡必须携带 APK 内置的 mTLS 客户端证书。

### 安装时提示签名不一致

说明当前设备中的 APK 与待安装 APK 使用了不同签名。只能卸载旧版本后安装，或者使用与旧版本相同的签名重新构建。卸载会清除应用本地数据，包括通关进度。

### 重新打包后关卡行为异常

部分关卡会校验 APK 签名、代码段 CRC、Native 指令或响应签名。重新打包、修改 Smali、Patch SO 或 Hook 校验器后，关卡可能主动失败或静默返回错误，这属于靶场逻辑的一部分。
