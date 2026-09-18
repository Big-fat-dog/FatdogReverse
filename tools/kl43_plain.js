/* KL43 桥上听风 —— JSBridge 前端消息构造与消息签名（混淆原料，真源文件）
 * 被 tools/gen_kl43.py 读取：先 javascript-obfuscator 混淆，再写 app/assets/h5/bridge_kl43.html。
 * 明文仅供本地生成/自警使用，绝不直接进 APK。
 *
 * 协议：bridge 消息 = { cmd, page, ts, sign }
 *   cmd  = 指令（"q" 查询 / "v" 版本 / "p" 心跳）
 *   sign = HMAC-SHA256(MSG_KEY, "cmd=<cmd>&page=<page>&ts=<ts>")  ← 在 JS 侧计算
 */
(function () {
  var MSG_KEY = "Fatdog_coral"; // 消息签名密钥（真钥，藏在混淆后）

  var KK = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];

  function rr(x, n) { return (x >>> n) | (x << (32 - n)); }

  function s2b(s) {
    var b = [];
    for (var i = 0; i < s.length; i++) b.push(s.charCodeAt(i) & 0xff);
    return b;
  }

  function sha256(bytes) {
    var m = bytes.slice();
    var l = m.length * 8;
    m.push(0x80);
    while (m.length % 64 !== 56) m.push(0);
    m.push(0, 0, 0, 0);
    m.push((l >>> 24) & 0xff, (l >>> 16) & 0xff, (l >>> 8) & 0xff, l & 0xff);
    var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    for (var off = 0; off < m.length; off += 64) {
      var w = [];
      for (var i = 0; i < 16; i++) {
        var j = off + i * 4;
        w[i] = (((m[j] << 24) | (m[j + 1] << 16) | (m[j + 2] << 8) | m[j + 3]) >>> 0);
      }
      for (var i2 = 16; i2 < 64; i2++) {
        var s0 = rr(w[i2 - 15], 7) ^ rr(w[i2 - 15], 18) ^ (w[i2 - 15] >>> 3);
        var s1 = rr(w[i2 - 2], 17) ^ rr(w[i2 - 2], 19) ^ (w[i2 - 2] >>> 10);
        w[i2] = (w[i2 - 16] + s0 + w[i2 - 7] + s1) >>> 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (var i3 = 0; i3 < 64; i3++) {
        var S1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25);
        var ch = (e & f) ^ ((~e) & g);
        var t1 = (hh + S1 + ch + KK[i3] + w[i3]) >>> 0;
        var S0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22);
        var mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
      h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
    }
    var out = [];
    for (var i4 = 0; i4 < 8; i4++) {
      out.push((h[i4] >>> 24) & 0xff, (h[i4] >>> 16) & 0xff, (h[i4] >>> 8) & 0xff, h[i4] & 0xff);
    }
    return out;
  }

  function hex(b) {
    var s = "";
    for (var i = 0; i < b.length; i++) s += ("0" + b[i].toString(16)).slice(-2);
    return s;
  }

  function hmacSha256Hex(key, msg) {
    var kb = s2b(key);
    while (kb.length < 64) kb.push(0);
    var ip = [], op = [];
    for (var i = 0; i < 64; i++) { ip.push(kb[i] ^ 0x36); op.push(kb[i] ^ 0x5c); }
    var inner = sha256(ip.concat(s2b(msg)));
    return hex(sha256(op.concat(inner)));
  }

  // 构造一条 bridge 消息（含 JS 侧签名）
  function buildMsg(cmd, page, ts) {
    var payload = "cmd=" + cmd + "&page=" + page + "&ts=" + ts;
    var sign = hmacSha256Hex(MSG_KEY, payload);
    return JSON.stringify({ cmd: cmd, page: page, ts: ts, sign: sign });
  }

  // 宿主/页面调用入口：查询指令
  function fdMsg(page, ts) {
    return buildMsg("q", page, ts);
  }

  if (typeof window !== "undefined") { window.fdMsg = fdMsg; }
  if (typeof module !== "undefined" && module.exports) {
    module.exports = { fdMsg: fdMsg, buildMsg: buildMsg };
  }
})();
