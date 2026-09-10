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

## 网络关卡启动

服务端共监听三个端口：

| 端口 | 协议 | 适用关卡 |
|---|---|---|
| `8787` | HTTP | `L15-L19`、`KKL2-KKL5` |
| `8443` | HTTPS | `L21-L25`、`L27-L37`、`L43-L53`、`KL6-KL10`、`KL30` |
| `8444` | HTTPS + mTLS | `L26` |

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

### 模拟器

模拟器会自动使用 `10.0.2.2` 访问宿主机，不需要执行 `adb reverse`。

### 真机

真机的 `127.0.0.1` 指向手机自身，因此需要通过 ADB 将电脑端口映射到手机：

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
