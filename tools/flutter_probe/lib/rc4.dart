/// 极简 RC4 流密码 —— 纯 Dart 实现，不依赖第三方包。
///
/// 用途：碧落天 KL40b「镜中之障」的业务侧对称加密（产物中的真实 Dart 代码）。
/// 与主工程伴生 so（`kl40b.cpp` 的 `sigil_ns::rc4_hex`）及服务端（`server.py::_rc4_53`）
/// 三侧同口径：
///   KL40b：enc = RC4( SHA-256(key || "|rc4"),  "page=<page>&ts=<ts>" )  → 小写 hex
library fatdog_rc4;

const String _HEX = '0123456789abcdef';

/// RC4 加/解密（对称，同一函数），输出小写 hex
String rc4Hex(List<int> key, String plain) {
  final s = List<int>.generate(256, (i) => i);
  final klen = key.isEmpty ? 1 : key.length;
  var j = 0;
  for (var i = 0; i < 256; i++) {
    j = (j + s[i] + (key[i % klen] & 0xff)) & 0xff;
    final t = s[i];
    s[i] = s[j];
    s[j] = t;
  }

  var x = 0, y = 0;
  final sb = StringBuffer();
  for (final ch in plain.codeUnits) {
    x = (x + 1) & 0xff;
    y = (y + s[x]) & 0xff;
    final t = s[x];
    s[x] = s[y];
    s[y] = t;
    final k = s[(s[x] + s[y]) & 0xff];
    final c = (ch & 0xff) ^ k;
    sb.write(_HEX[(c >> 4) & 0xf]);
    sb.write(_HEX[c & 0xf]);
  }
  return sb.toString();
}
