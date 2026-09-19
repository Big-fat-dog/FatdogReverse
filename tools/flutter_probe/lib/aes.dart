/// 极简 AES-128（仅加密，ECB / CBC 两种模式 + PKCS#7）—— 纯 Dart 实现，不依赖第三方包。
///
/// 用途：碧落天 KL37「风中鸢尾」/ KL38「雾里观花」的业务侧加密（产物中的真实 Dart 代码）。
/// 与主工程伴生 so（`kl37.cpp` / `kl38.cpp`）及服务端（server.py 纯标准库 AES）三侧同口径：
///   KL37：enc = AES-128-ECB-PKCS7(key, "page=<page>&ts=<ts>")            → 小写 hex
///   KL38：enc = AES-128-CBC-PKCS7(key, iv||"page=<page>&ts=<ts>")        → 小写 hex（前置 IV）
library fatdog_aes;

const List<int> _SBOX = [
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

const List<int> _RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

int _xtime(int x) => ((x << 1) ^ ((x >> 7) * 0x1b)) & 0xff;

/// 密钥扩展：16 或 32 字节密钥 → (轮密钥, 轮数)
(List<int>, int) _expandKey(List<int> key) {
  final nk = key.length ~/ 4;
  final nr = nk + 6;
  final total = 4 * (nr + 1);
  final rk = List<int>.filled(total * 4, 0);
  for (var i = 0; i < key.length && i < total * 4; i++) {
    rk[i] = key[i] & 0xff;
  }
  for (var i = nk; i < total; i++) {
    final t = <int>[
      rk[(i - 1) * 4],
      rk[(i - 1) * 4 + 1],
      rk[(i - 1) * 4 + 2],
      rk[(i - 1) * 4 + 3],
    ];
    if (i % nk == 0) {
      final tmp = t[0];
      t[0] = _SBOX[t[1]] ^ _RCON[i ~/ nk];
      t[1] = _SBOX[t[2]];
      t[2] = _SBOX[t[3]];
      t[3] = _SBOX[tmp];
    } else if (nk > 6 && i % nk == 4) {
      for (var k = 0; k < 4; k++) {
        t[k] = _SBOX[t[k]];
      }
    }
    for (var k = 0; k < 4; k++) {
      rk[i * 4 + k] = (rk[(i - nk) * 4 + k] ^ t[k]) & 0xff;
    }
  }
  return (rk, nr);
}

/// 单块加密（16 字节 → 16 字节），轮数由密钥长度决定（128→10，256→14）
List<int> _encryptBlock(List<int> rk, int rounds, List<int> input) {
  final s = List<int>.generate(16, (i) => (input[i] ^ rk[i]) & 0xff);
  for (var round = 1; round <= rounds; round++) {
    // SubBytes + ShiftRows
    final t = List<int>.filled(16, 0);
    for (var c = 0; c < 4; c++) {
      for (var r = 0; r < 4; r++) {
        t[c * 4 + r] = _SBOX[s[((c + r) % 4) * 4 + r]];
      }
    }
    for (var i = 0; i < 16; i++) {
      s[i] = t[i];
    }
    // MixColumns（末轮不做）
    if (round != rounds) {
      for (var c = 0; c < 4; c++) {
        final p = c * 4;
        final a0 = s[p], a1 = s[p + 1], a2 = s[p + 2], a3 = s[p + 3];
        final x = a0 ^ a1 ^ a2 ^ a3;
        s[p] = (s[p] ^ x ^ _xtime(a0 ^ a1)) & 0xff;
        s[p + 1] = (s[p + 1] ^ x ^ _xtime(a1 ^ a2)) & 0xff;
        s[p + 2] = (s[p + 2] ^ x ^ _xtime(a2 ^ a3)) & 0xff;
        s[p + 3] = (s[p + 3] ^ x ^ _xtime(a3 ^ a0)) & 0xff;
      }
    }
    // AddRoundKey
    for (var i = 0; i < 16; i++) {
      s[i] = (s[i] ^ rk[round * 16 + i]) & 0xff;
    }
  }
  return s;
}

const String _HEX = '0123456789abcdef';

/// AES-128-ECB + PKCS#7，输出小写 hex
String aes128EcbPkcs7Hex(List<int> key, String plain) {
  final key16 = List<int>.filled(16, 0);
  for (var i = 0; i < 16 && i < key.length; i++) {
    key16[i] = key[i] & 0xff;
  }
  final (rk, rounds) = _expandKey(key16);

  final buf = <int>[];
  for (final b in plain.codeUnits) {
    buf.add(b & 0xff);
  }
  final pad = 16 - (buf.length % 16);
  for (var i = 0; i < pad; i++) {
    buf.add(pad);
  }

  final sb = StringBuffer();
  for (var off = 0; off < buf.length; off += 16) {
    final blk = _encryptBlock(rk, rounds, buf.sublist(off, off + 16));
    for (final b in blk) {
      sb.write(_HEX[(b >> 4) & 0xf]);
      sb.write(_HEX[b & 0xf]);
    }
  }
  return sb.toString();
}

/// AES-128-CBC + PKCS#7，输出小写 hex（**IV 前置**在密文之前）
///
/// KL38 用：iv 由 native 侧随机生成，随密文一起发给服务端；服务端剥下前 16 字节做 IV 解密。
String aes128CbcPkcs7Hex(List<int> key, List<int> iv16, String plain) {
  final key16 = List<int>.filled(16, 0);
  for (var i = 0; i < 16 && i < key.length; i++) {
    key16[i] = key[i] & 0xff;
  }
  final (rk, rounds) = _expandKey(key16);

  final buf = <int>[];
  for (final b in plain.codeUnits) {
    buf.add(b & 0xff);
  }
  final pad = 16 - (buf.length % 16);
  for (var i = 0; i < pad; i++) {
    buf.add(pad);
  }

  final sb = StringBuffer();
  for (var i = 0; i < 16; i++) {
    final b = iv16[i] & 0xff;
    sb.write(_HEX[(b >> 4) & 0xf]);
    sb.write(_HEX[b & 0xf]);
  }

  var prev = List<int>.generate(16, (i) => iv16[i] & 0xff);
  for (var off = 0; off < buf.length; off += 16) {
    final x = List<int>.generate(16, (i) => (buf[off + i] ^ prev[i]) & 0xff);
    final blk = _encryptBlock(rk, rounds, x);
    prev = blk;
    for (final b in blk) {
      sb.write(_HEX[(b >> 4) & 0xf]);
      sb.write(_HEX[b & 0xf]);
    }
  }
  return sb.toString();
}

// ============================================================
// AES-GCM（CTR + GHASH；AAD 为空）
// ============================================================

/// GF(2^128) 乘法（GCM 约定，NIST SP 800-38D 的位移方向）
List<int> _gfMul(List<int> x, List<int> h) {
  final z = List<int>.filled(16, 0);
  final v = List<int>.from(h);
  for (var i = 0; i < 128; i++) {
    final bit = (x[i >> 3] >> (7 - (i & 7))) & 1;
    if (bit == 1) {
      for (var j = 0; j < 16; j++) {
        z[j] ^= v[j];
      }
    }
    final lsb = v[15] & 1;
    for (var j = 15; j > 0; j--) {
      v[j] = ((v[j] >> 1) | ((v[j - 1] & 1) << 7)) & 0xff;
    }
    v[0] = (v[0] >> 1) & 0xff;
    if (lsb == 1) v[0] ^= 0xe1;
  }
  return z;
}

/// AES-GCM 加密（12 字节 nonce、空 AAD），输出 hex(nonce || ct || tag)
///
/// key 长度可为 16（AES-128）或 32（AES-256）——KL40 的请求钥是 32 字节。
String aesGcmEncryptHex(List<int> key, List<int> nonce, String plain) {
  final (rk, rounds) = _expandKey(key);
  final h = _encryptBlock(rk, rounds, List<int>.filled(16, 0));
  final j0 = <int>[...nonce, 0x00, 0x00, 0x00, 0x01];
  final e0 = _encryptBlock(rk, rounds, j0);

  final pt = <int>[];
  for (final b in plain.codeUnits) {
    pt.add(b & 0xff);
  }

  // CTR
  final ct = <int>[];
  final ctr = List<int>.from(j0);
  for (var off = 0; off < pt.length; off += 16) {
    for (var i = 15; i >= 12; i--) {
      ctr[i] = (ctr[i] + 1) & 0xff;
      if (ctr[i] != 0) break;
    }
    final ks = _encryptBlock(rk, rounds, ctr);
    final n = (pt.length - off) < 16 ? (pt.length - off) : 16;
    for (var i = 0; i < n; i++) {
      ct.add((pt[off + i] ^ ks[i]) & 0xff);
    }
  }

  // GHASH
  var y = List<int>.filled(16, 0);
  for (var off = 0; off < ct.length; off += 16) {
    final blk = List<int>.filled(16, 0);
    final n = (ct.length - off) < 16 ? (ct.length - off) : 16;
    for (var i = 0; i < n; i++) {
      blk[i] = ct[off + i];
    }
    for (var i = 0; i < 16; i++) {
      y[i] ^= blk[i];
    }
    y = _gfMul(y, h);
  }
  final lb = List<int>.filled(16, 0);
  final clen = ct.length * 8;
  for (var i = 0; i < 8; i++) {
    lb[15 - i] = (clen >> (i * 8)) & 0xff;
  }
  for (var i = 0; i < 16; i++) {
    y[i] ^= lb[i];
  }
  y = _gfMul(y, h);
  final tag = List<int>.generate(16, (i) => (y[i] ^ e0[i]) & 0xff);

  final sb = StringBuffer();
  for (final b in <int>[...nonce, ...ct, ...tag]) {
    sb.write(_HEX[(b >> 4) & 0xf]);
    sb.write(_HEX[b & 0xf]);
  }
  return sb.toString();
}
