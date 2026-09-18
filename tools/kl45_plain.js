/* KL45 深渊合璧 —— JS 层加密（收官卷）
 *
 * 混淆原料，真源文件。被 tools/gen_kl45.py 读取：混淆后写 app/assets/h5/hybrid_kl45.html。
 *
 * 本关是须弥界收官卷，把前四关的手段收束成两道锁：
 *   第一层（本文件，JS 层）：用 AES-128-ECB + PKCS7 把明文 "page=<page>&ts=<ts>" 加密成 hex 串，
 *                            密钥 AES_KEY 藏在被搅乱的代码里（原文里看不见，得自己解）。
 *   第二层（native，libhybrid.so）：对 "Fatdog_abyss|page=..&ts=..&enc=.." 取一次普通 MD5 作为签名。
 * 两层的钥不同、算法不同，缺哪一层服务端都不放数。
 */
(function () {
  var AES_KEY = "Fatdog_abyss"; // JS 层 AES 密钥（真钥，藏在混淆后）

  // AES 标准 S-box（写成 hex 串再解析，混淆后会被字符串数组编码藏起来）
  var SBOX_HEX =
    "637c777bf26b6fc53001672bfed7ab76" +
    "ca82c97dfa5947f0add4a2af9ca472c0" +
    "b7fd9326363ff7cc34a5e5f171d83115" +
    "04c723c31896059a071280e2eb27b275" +
    "09832c1a1b6e5aa0523bd6b329e32f84" +
    "53d100ed20fcb15b6acbbe394a4c58cf" +
    "d0efaafb434d338545f9027f503c9fa8" +
    "51a3408f929d38f5bcb6da2110fff3d2" +
    "cd0c13ec5f974417c4a77e3d645d1973" +
    "60814fdc222a908846eeb814de5e0bdb" +
    "e0323a0a4906245cc2d3ac629195e479" +
    "e7c8376d8dd54ea96c56f4ea657aae08" +
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a" +
    "703eb5664803f60e613557b986c11d9e" +
    "e1f8981169d98e949b1e87e9ce5528df" +
    "8ca1890dbfe6426841992d0fb054bb16";
  var RCON = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54];

  function hexToBytes(h) {
    var a = [];
    for (var i = 0; i < h.length; i += 2) a.push(parseInt(h.substr(i, 2), 16));
    return a;
  }

  var SBOX = hexToBytes(SBOX_HEX);

  // 密钥补零到 16 字节（AES-128）
  function keyBytes(s) {
    var k = [];
    for (var i = 0; i < 16; i++) k.push(i < s.length ? (s.charCodeAt(i) & 0xff) : 0);
    return k;
  }

  // AES-128 密钥扩展 → 176 字节（11 组轮密钥）
  function expandKey(key) {
    var w = key.slice();
    for (var i = 4; i < 44; i++) {
      var a = w[(i - 1) * 4], b = w[(i - 1) * 4 + 1], c = w[(i - 1) * 4 + 2], d = w[(i - 1) * 4 + 3];
      if (i % 4 === 0) {
        var tmp = a;
        a = SBOX[b] ^ RCON[i / 4 - 1];
        b = SBOX[c];
        c = SBOX[d];
        d = SBOX[tmp];
      }
      w.push(w[(i - 4) * 4] ^ a);
      w.push(w[(i - 4) * 4 + 1] ^ b);
      w.push(w[(i - 4) * 4 + 2] ^ c);
      w.push(w[(i - 4) * 4 + 3] ^ d);
    }
    return w;
  }

  function addRoundKey(s, rk, round) {
    for (var i = 0; i < 16; i++) s[i] ^= rk[round * 16 + i];
  }

  function subBytes(s) {
    for (var i = 0; i < 16; i++) s[i] = SBOX[s[i]];
  }

  // 行移位：第 r 行循环左移 r
  function shiftRows(s) {
    var t = s.slice();
    for (var r = 0; r < 4; r++) {
      for (var c = 0; c < 4; c++) s[r + 4 * c] = t[r + 4 * ((c + r) % 4)];
    }
  }

  // GF(2^8) 乘法
  function gf(a, b) {
    var p = 0;
    for (var i = 0; i < 8; i++) {
      if (b & 1) p ^= a;
      var hi = a & 0x80;
      a = (a << 1) & 0xff;
      if (hi) a ^= 0x1b;
      b >>= 1;
    }
    return p & 0xff;
  }

  function mixColumns(s) {
    for (var c = 0; c < 4; c++) {
      var i0 = c * 4;
      var a0 = s[i0], a1 = s[i0 + 1], a2 = s[i0 + 2], a3 = s[i0 + 3];
      s[i0]     = gf(2, a0) ^ gf(3, a1) ^ a2 ^ a3;
      s[i0 + 1] = a0 ^ gf(2, a1) ^ gf(3, a2) ^ a3;
      s[i0 + 2] = a0 ^ a1 ^ gf(2, a2) ^ gf(3, a3);
      s[i0 + 3] = gf(3, a0) ^ a1 ^ a2 ^ gf(2, a3);
    }
  }

  function encBlock(rk, blk) {
    var s = blk.slice();
    addRoundKey(s, rk, 0);
    for (var round = 1; round < 10; round++) {
      subBytes(s); shiftRows(s); mixColumns(s); addRoundKey(s, rk, round);
    }
    subBytes(s); shiftRows(s); addRoundKey(s, rk, 10);
    return s;
  }

  // PKCS#7 补齐
  function pkcs7(bytes) {
    var n = 16 - (bytes.length % 16);
    var out = bytes.slice();
    for (var i = 0; i < n; i++) out.push(n);
    return out;
  }

  function toHex(b) {
    var s = "";
    for (var i = 0; i < b.length; i++) s += ("0" + b[i].toString(16)).slice(-2);
    return s;
  }

  // 第一层：把明文参数 AES 加密成 enc（hex）
  function fdPack(page, ts) {
    var pt = "page=" + page + "&ts=" + ts;
    var bytes = [];
    for (var i = 0; i < pt.length; i++) bytes.push(pt.charCodeAt(i) & 0xff);
    var rk = expandKey(keyBytes(AES_KEY));
    var padded = pkcs7(bytes);
    var out = [];
    for (var o = 0; o < padded.length; o += 16) {
      var c = encBlock(rk, padded.slice(o, o + 16));
      for (var k = 0; k < 16; k++) out.push(c[k]);
    }
    return toHex(out);
  }

  if (typeof window !== "undefined") { window.fdPack = fdPack; }
  if (typeof module !== "undefined" && module.exports) { module.exports = { fdPack: fdPack }; }
})();
