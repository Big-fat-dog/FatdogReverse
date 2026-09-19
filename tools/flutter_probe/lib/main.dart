// 碧落天 Flutter 载荷 —— 探针工程的业务代码（KL36 / KL37 共用一份产物）
//
// 说明：本工程**不是** FatdogReverse 主 App 的一部分，它只用来产出**真实的 Flutter 产物**：
//   - lib/arm64-v8a/libapp.so   （Dart AOT 快照，本文件编译后的业务代码）
//   - lib/arm64-v8a/libflutter.so（Flutter 引擎）
//   - assets/flutter_assets/     （资源）
// 构建脚本 tools/build_flutter_artifacts.py 抽出来后放进主工程 app/libs 与 app/assets，
// 作为关卡的真实逆向对象（Blutter / reFlutter / IDA / Ghidra 的目标）。
//
// 两条重要经验（都踩过）：
//   1) Dart AOT 会**树摇未被引用的常量**——哨兵/密钥/诱饵常量都必须在 `_probeSelfCheck()`
//      里被真实读写，否则会被彻底删掉、产物里搜不到（诱饵删掉会让"两个标记一真一假"落空）。
//   2) 字符串常量在对象池里**可能被排到相邻位置**——若密钥拆成两段字符串字面量，strings
//      可能一口气读全，分裂就白做了。故 KL37 的第二瓣改用**码元数组**存放。
//
// 关卡口径（与主工程伴生 so、server.py 完全一致）：
//   KL36：sign = MD5("page=<page>&ts=<ts>&k=<KEY>")
//   KL37：enc  = AES-128-ECB-PKCS7(key, "page=<page>&ts=<ts>")

import 'dart:convert';
import 'dart:ffi';

import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';

import 'aes.dart';

// ============================ KL36 ============================

/// KL36 资源标识哨兵（对象池定位用）
const String kBundleTag = 'FDK36|Fatdog_scroll|END';

/// KL36 签名密钥（真）；诱饵与真钥仅差一个字母
const String kSignKey = 'Fatdog_scroll';
const String kDecoyKey = 'Fatdog_roll';

/// KL36 签名原文模板
String signMaterial(int page, int ts, String key) => 'page=$page&ts=$ts&k=$key';

/// KL36 正式签名：MD5（本关只用这一个摘要原语）
String buildSign(int page, int ts) =>
    md5.convert(utf8.encode(signMaterial(page, ts, kSignKey))).toString();

/// KL36 诱饵签名（仅对照，不用于请求）
String buildDecoySign(int page, int ts) =>
    md5.convert(utf8.encode(signMaterial(page, ts, kDecoyKey))).toString();

// ============================ KL37 ============================
// 密钥拆两瓣：第一瓣是字符串字面量；第二瓣以"码元数组"存放——
// 于是 strings 只能抓到半截，另一瓣要在对象池里认出这个整数数组才拿得到。

const String kKiteTag = 'FDK37';
const String kKiteP1 = 'Fatdog_';
const List<int> kKiteP2Codes = [0x6b, 0x69, 0x74, 0x65]; // 'kite'

/// 拼接后的完整 AES 密钥
String kiteKey() => '$kKiteP1${String.fromCharCodes(kKiteP2Codes)}';

/// KL37 请求加密：AES-128-ECB + PKCS#7（本关只此一种对称加密，无摘要、无 HMAC）
String buildKiteEnc(int page, int ts) =>
    aes128EcbPkcs7Hex(kiteKey().codeUnits, 'page=$page&ts=$ts');

/// KL37 诱饵密钥 + 其加密结果（仅对照）
const String kKiteDecoy = 'Fatdog_sail';
String buildKiteDecoyEnc(int page, int ts) =>
    aes128EcbPkcs7Hex(kKiteDecoy.codeUnits, 'page=$page&ts=$ts');

// ============================ KL38 ============================
// 本关考点在**证书固定绕过**，密钥不再拆分，直接作为字符串字面量放在业务代码里；
// AES 密钥由主密钥派生：SHA256("<主密钥>|aes") 的前 16 字节。

const String kHazeTag = 'FDK38|Fatdog_haze|END';
const String kHazeKey = 'Fatdog_haze';
const String kHazeDecoy = 'Fatdog_fog';

/// 演示用固定 IV（真实运行时 IV 由 native 侧随机生成并前置在密文之前）
const List<int> kHazeIv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// AES-128 密钥 = SHA256("<主密钥>|aes") 的前 16 字节
List<int> hazeAesKey() =>
    sha256.convert(utf8.encode('$kHazeKey|aes')).bytes.sublist(0, 16);

/// KL38 请求加密：AES-128-CBC + PKCS#7（IV 前置）
String buildHazeEnc(int page, int ts) =>
    aes128CbcPkcs7Hex(hazeAesKey(), kHazeIv, 'page=$page&ts=$ts');

/// KL38 摘要：SHA256(enc + 主密钥) 的十六进制前 16 位（普通摘要，非 HMAC）
String buildHazeSign(String enc) =>
    sha256.convert(utf8.encode('$enc$kHazeKey')).toString().substring(0, 16);

/// KL38 诱饵密钥的加密结果（仅对照：服务端会以此判 403）
String buildHazeDecoyEnc(int page, int ts) => aes128CbcPkcs7Hex(
    sha256.convert(utf8.encode('$kHazeDecoy|aes')).bytes.sublist(0, 16),
    kHazeIv,
    'page=$page&ts=$ts');

// ============================ KL39 ============================
// 密钥被掰成两瓣：**这一瓣在这里**（对象池），另一瓣在 native（libbow.so）。
// 摘要由 Dart 侧算，对称加密交给 C —— 通过 dart:ffi 调用（`fd_moon_enc`）。

const String kMoonTag = 'FDK39|Fatdog_m|END';
const String kMoonP1 = 'Fatdog_m'; // Dart 侧那一瓣（8 字节）
const String kMoonDecoyP1 = 'Fatdog_s';
const String kMoonDecoyP2 = 'tar';

/// Dart 侧摘要：MD5("page=<page>&ts=<ts>") 的 16 字节原始摘要
List<int> moonDigest(int page, int ts) =>
    md5.convert(utf8.encode('page=$page&ts=$ts')).bytes;

/// 摘要的 hex 形态（跨边界传给 native 时用）
String moonDigestHex(int page, int ts) =>
    md5.convert(utf8.encode('page=$page&ts=$ts')).toString();

// ---- dart:ffi 绑定：Dart → C ----
// 注意：`Utf8` 属于 package:ffi，本工程不带该依赖，故用 dart:ffi 内置的 `Char`。

typedef _FdMoonEncNative = Pointer<Char> Function(Int32 page, Int64 ts);
typedef _FdMoonEncDart = Pointer<Char> Function(int page, int ts);

/// 调用 native 侧导出的 `fd_moon_enc`（Blutter 的 asm/ 里能看到这个调用点与符号名）
Pointer<Char>? ffiMoonEnc(int page, int ts) {
  try {
    final DynamicLibrary lib = DynamicLibrary.open('libbow.so');
    final _FdMoonEncDart enc =
        lib.lookupFunction<_FdMoonEncNative, _FdMoonEncDart>('fd_moon_enc');
    return enc(page, ts);
  } catch (_) {
    return null; // 载荷工程里没有这个 so，属预期
  }
}

bool ffiProbe() => ffiMoonEnc(1, 1787013761) != null;

/// 主密钥的两瓣以拼接方式呈现（教学对照：左半在 Dart、右半在 native）
String moonFragments() => '$kMoonP1 + <native>';

// ============================ KL40 ============================
// 收官卷：三原语叠加 —— 请求用 AES-256-GCM 封（带完整性标签）、
// 签名用普通 MD5、**响应换一把 AES 钥**回来。两把钥都由同一个标记派生。

const String kMirrorTag = 'FDK40|Fatdog_reflect|END';
const String kMirrorKey = 'Fatdog_reflect';
const String kMirrorDecoy = 'Fatdog_echo';

/// 请求钥：AES-256（32 字节）
List<int> mirrorReqKey() =>
    sha256.convert(utf8.encode('$kMirrorKey|req')).bytes;

/// 响应钥：AES-128（16 字节）—— 与请求钥不同，这就是"换钥"
List<int> mirrorRespKey() =>
    sha256.convert(utf8.encode('$kMirrorKey|resp')).bytes.sublist(0, 16);

/// 演示用固定 nonce（真实运行时由 native 随机生成并前置在密文之前）
const List<int> kMirrorNonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

/// 请求加密：AES-256-GCM，输出 hex(nonce || ct || tag)
String buildMirrorEnc(int page, int ts) =>
    aesGcmEncryptHex(mirrorReqKey(), kMirrorNonce, 'page=$page&ts=$ts');

/// 签名：普通 MD5 摘要（非 HMAC）
String buildMirrorSign(int page, int ts, String enc) => md5
    .convert(utf8.encode('page=$page&ts=$ts&enc=$enc&k=$kMirrorKey'))
    .toString();

/// 诱饵钥的加密结果（仅对照：服务端会 403）
String buildMirrorDecoyEnc(int page, int ts) => aesGcmEncryptHex(
    sha256.convert(utf8.encode('$kMirrorDecoy|req')).bytes,
    kMirrorNonce,
    'page=$page&ts=$ts');

/// 探针自检：显式引用**全部**哨兵/密钥/诱饵常量，避免被 AOT 树摇；
/// 同时确认两条签名/加密链路可用（debugPrint 在 release 下不输出，但实参会被求值）。
String _probeSelfCheck() {
  final String s36 = buildSign(1, 1787013761);
  final String d36 = buildDecoySign(1, 1787013761);
  final String e37 = buildKiteEnc(1, 1787013761);
  final String d37 = buildKiteDecoyEnc(1, 1787013761);
  final String e38 = buildHazeEnc(1, 1787013761);
  final String g38 = buildHazeSign(e38);
  final String d38 = buildHazeDecoyEnc(1, 1787013761);
  final String m39 = moonDigestHex(1, 1787013761);
  final bool f39 = ffiProbe();
  final String frag39 = moonFragments();
  final String e40 = buildMirrorEnc(1, 1787013761);
  final String g40 = buildMirrorSign(1, 1787013761, e40);
  final String d40 = buildMirrorDecoyEnc(1, 1787013761);
  final String tag = '$kBundleTag|$kKiteTag|$kKiteP1|${kKiteP2Codes.length}|'
      '$kKiteDecoy|$kHazeTag|$kHazeDecoy|${kHazeIv.length}|'
      '$kMoonTag|$kMoonDecoyP1|$kMoonDecoyP2|$kMirrorTag|$kMirrorDecoy|'
      '${kMirrorNonce.length}|${mirrorRespKey().length}';
  debugPrint('probe tag=$tag s36=$s36 d36=$d36 e37=$e37 d37=$d37 e38=$e38 g38=$g38 d38=$d38 '
      'm39=$m39 f39=$f39 frag39=$frag39 e40=$e40 g40=$g40 d40=$d40');
  return '$tag|$s36|$d36|$e37|$d37|$e38|$g38|$d38|$m39|$f39|$frag39|$e40|$g40|$d40';
}

void main() => runApp(const ProbeApp());

class ProbeApp extends StatelessWidget {
  const ProbeApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'probe',
      home: Scaffold(
        appBar: AppBar(title: const Text('probe')),
        body: Center(
          child: ElevatedButton(
            child: const Text('sign'),
            onPressed: () {
              final String r = _probeSelfCheck();
              debugPrint('probe=$r');
            },
          ),
        ),
      ),
    );
  }
}
