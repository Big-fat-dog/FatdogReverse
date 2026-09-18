/* KL44 暗流涌动 —— JSBridge 签名拦截（JS 层加密 payload）
 *
 * 混淆原料，真源文件。被 tools/gen_kl44.py 读取：混淆后写 app/assets/h5/sign_kl44.html。
 *
 * 双层设计：
 *   第一层（本文件，JS 层）：用 RC4 把明文 "page=<page>&ts=<ts>" 加密成 hex 串 enc，密钥 ENC_KEY 藏在 JS 里。
 *   第二层（native，libsignbridge.so）：对 "page=..&ts=..&enc=.." 再做一次 HMAC-SHA256 签名。
 *   两层的钥不同、算法不同——都得还原。
 */
(function () {
  var ENC_KEY = "Fatdog_pearl"; // JS 层加密密钥（真钥，藏在混淆后）

  function s2b(s) {
    var b = [];
    for (var i = 0; i < s.length; i++) b.push(s.charCodeAt(i) & 0xff);
    return b;
  }

  function rc4(key, data) {
    var S = [];
    for (var i = 0; i < 256; i++) S[i] = i;
    var j = 0;
    for (var i2 = 0; i2 < 256; i2++) {
      j = (j + S[i2] + key[i2 % key.length]) & 0xff;
      var t = S[i2]; S[i2] = S[j]; S[j] = t;
    }
    var out = [];
    var i3 = 0, j3 = 0;
    for (var k = 0; k < data.length; k++) {
      i3 = (i3 + 1) & 0xff;
      j3 = (j3 + S[i3]) & 0xff;
      var t2 = S[i3]; S[i3] = S[j3]; S[j3] = t2;
      out.push(data[k] ^ S[(S[i3] + S[j3]) & 0xff]);
    }
    return out;
  }

  function hex(b) {
    var s = "";
    for (var i = 0; i < b.length; i++) s += ("0" + b[i].toString(16)).slice(-2);
    return s;
  }

  // 第一层：把明文参数加密成 enc（hex）
  function fdEnc(page, ts) {
    var pt = "page=" + page + "&ts=" + ts;
    return hex(rc4(s2b(ENC_KEY), s2b(pt)));
  }

  if (typeof window !== "undefined") { window.fdEnc = fdEnc; }
  if (typeof module !== "undefined" && module.exports) { module.exports = { fdEnc: fdEnc }; }
})();
