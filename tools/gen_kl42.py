# -*- coding: utf-8 -*-
"""KL42 沙中藏贝 —— 生成加密 H5 资源容器 app/assets/h5/vault_kl42.bin

流程：
  1. 读 tools/kl42_plain.js（前端明文签名脚本，仓库内可复现的真源）
  2. 用 javascript-obfuscator 混淆（stringArray + rc4 编码 + 控制流平坦化 + 拆分字符串）
  3. 把混淆结果包进 HTML 模板
  4. RC4(key=b"Fatdog_vault") 加密整段 HTML
  5. 写入 app/assets/h5/vault_kl42.bin

依赖：node + javascript-obfuscator。
  隔离安装：npm install javascript-obfuscator --prefix <node 工作区>
用法：
  D:/python39/python.exe tools/gen_kl42.py            # 正常（混淆）
  D:/python39/python.exe tools/gen_kl42.py --no-obf   # 调试（不混淆）
"""
import io, os, sys, subprocess, hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAIN_JS = os.path.join(ROOT, 'tools', 'kl42_plain.js')
OUT_BIN = os.path.join(ROOT, 'app', 'assets', 'h5', 'vault_kl42.bin')
CONTAINER_KEY = b"Fatdog_vault"

NODE_CANDS = [
    r'C:\Users\21494\.workbuddy\binaries\node\versions\22.22.2-3\node.exe',
    r'D:\nvm\nodejs\node.exe',
    'node',
]
OBF_CANDS = [
    r'C:\Users\21494\.workbuddy\binaries\node\workspace\node_modules',
    os.path.join(ROOT, 'node_modules'),
]


def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for ch in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(ch ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


HTML = u'''<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>藏贝台 · 资源</title>
<style>
  html,body{margin:0;padding:0;background:#0e1014;color:#d7dbe6;font-family:ui-monospace,Menlo,Consolas,monospace}
  .wrap{padding:12px 14px}
  h3{margin:4px 0 10px;font-size:15px;color:#8fd8c0;letter-spacing:1px}
  .card{background:#161a20;border:1px solid #232a33;border-radius:10px;padding:10px 12px;font-size:12px;line-height:1.7;word-break:break-all}
  .tip{color:#6f7a92;font-size:12px;margin-top:8px}
</style>
</head>
<body>
<div class="wrap">
  <h3>藏贝台 · 密签</h3>
  <div class="card">页面资源已由 native 解密后载入。签名在本页脚本内计算，不落盘、不外传。</div>
  <div class="tip" id="tip">签在暗处。</div>
</div>
<script>
//__FD_JS__
</script>
<script>
try {
  var _p = fdSign(1, Math.floor(Date.now() / 1000));
  document.getElementById('tip').textContent = '签名模块已就绪';
} catch (e) {
  document.getElementById('tip').textContent = 'script err: ' + e;
}
</script>
</body>
</html>
'''

DRIVER = u'''const fs = require('fs');
const O = require('javascript-obfuscator');
const src = fs.readFileSync(process.argv[2], 'utf8');
const res = O.obfuscate(src, {
  seed: 20280902,
  compact: true,
  identifierNamesGenerator: 'hexadecimal',
  identifiersPrefix: 'fd',
  stringArray: true,
  stringArrayEncoding: ['rc4'],
  stringArrayThreshold: 0.85,
  stringArrayRotate: true,
  stringArrayShuffle: true,
  splitStrings: true,
  splitStringsChunkLength: 5,
  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 0.5,
  numbersToExpressions: true,
  simplify: true,
  renameGlobals: false,
  selfDefending: false,
  debugProtection: false,
  disableConsoleOutput: false
});
const code = res.getObfuscatedCode();
fs.writeFileSync(process.argv[3], code, 'utf8');
console.log('obfuscated length:', code.length);
'''


def find_node():
    for c in NODE_CANDS:
        if c == 'node' or os.path.exists(c):
            return c
    sys.exit('node not found')


def find_obf():
    for c in OBF_CANDS:
        if os.path.isdir(os.path.join(c, 'javascript-obfuscator')):
            return c
    sys.exit('javascript-obfuscator not found (npm install javascript-obfuscator --prefix <node workspace>)')


def obfuscate(plain):
    node = find_node()
    obf = find_obf()
    tmp_driver = os.path.join(ROOT, '.workbuddy', 'kl42_ob_run.js')
    tmp_out = os.path.join(ROOT, '.workbuddy', 'kl42_obf.js')
    io.open(tmp_driver, 'w', encoding='utf-8').write(DRIVER)
    env = dict(os.environ)
    env['NODE_PATH'] = obf
    r = subprocess.run([node, tmp_driver, PLAIN_JS, tmp_out],
                       capture_output=True, text=True, encoding='utf-8',
                       errors='ignore', env=env)
    if r.returncode != 0:
        sys.exit('obfuscate failed:\n' + (r.stdout or '') + (r.stderr or ''))
    code = io.open(tmp_out, encoding='utf-8').read()
    print((r.stdout or '').strip())
    for f in (tmp_driver, tmp_out):
        if os.path.exists(f):
            os.remove(f)
    return code


def main():
    no_obf = '--no-obf' in sys.argv
    if not os.path.exists(PLAIN_JS):
        sys.exit('missing ' + PLAIN_JS)
    js = io.open(PLAIN_JS, encoding='utf-8').read()
    if no_obf:
        print('obfuscation SKIPPED (--no-obf)')
    else:
        js = obfuscate(js)
    html = HTML.replace('//__FD_JS__', js).encode('utf-8')
    enc = rc4(CONTAINER_KEY, html)
    os.makedirs(os.path.dirname(OUT_BIN), exist_ok=True)
    with io.open(OUT_BIN, 'wb') as f:
        f.write(enc)
    # 回解自证
    assert rc4(CONTAINER_KEY, enc) == html, 'round-trip mismatch'
    print('plain-html bytes :', len(html))
    print('container bytes  :', len(enc), '->', os.path.relpath(OUT_BIN, ROOT))
    print('container md5    :', hashlib.md5(enc).hexdigest())
    print('container key    :', CONTAINER_KEY.decode())
    print('round-trip OK')


if __name__ == '__main__':
    main()
