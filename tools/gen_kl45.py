# -*- coding: utf-8 -*-
"""KL45 深渊合璧 —— 生成 assets/h5/hybrid_kl45.html（内嵌 ob 混淆的 JS 层 AES 加密脚本）

流程：读 tools/kl45_plain.js → javascript-obfuscator 混淆 → 包 HTML → 写 assets/h5/hybrid_kl45.html。

依赖：node + javascript-obfuscator。
用法：
  D:/python39/python.exe tools/gen_kl45.py            # 正常（混淆）
  D:/python39/python.exe tools/gen_kl45.py --no-obf   # 调试（不混淆）
"""
import io, os, sys, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAIN_JS = os.path.join(ROOT, 'tools', 'kl45_plain.js')
OUT_HTML = os.path.join(ROOT, 'app', 'assets', 'h5', 'hybrid_kl45.html')

NODE_CANDS = [
    r'C:\Users\21494\.workbuddy\binaries\node\versions\22.22.2-3\node.exe',
    r'D:\nvm\nodejs\node.exe',
    'node',
]
OBF_CANDS = [
    r'C:\Users\21494\.workbuddy\binaries\node\workspace\node_modules',
    os.path.join(ROOT, 'node_modules'),
]

HTML = u'''<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>合璧 · 加密</title>
<style>
  html,body{margin:0;padding:0;background:#0a0d12;color:#cfd6e4;font-family:ui-monospace,Menlo,Consolas,monospace}
  .wrap{padding:12px 14px}
  h3{margin:4px 0 10px;font-size:15px;color:#7fd1c8;letter-spacing:1px}
  .card{background:#111720;border:1px solid #1e2733;border-radius:10px;padding:10px 12px;font-size:12px;line-height:1.7;word-break:break-all}
  .tip{color:#63708a;font-size:12px;margin-top:8px}
</style>
</head>
<body>
<div class="wrap">
  <h3>合璧 · 加密层</h3>
  <div class="card">深渊之下两道锁：本页先用分组密码把参数锁死，native 再压一道摘要签。分开的两把钥，分开的两道算法。</div>
  <div class="tip" id="tip">深渊未动。</div>
</div>
<script>
//__FD_JS__
</script>
<script>
try {
  var _e = fdPack(1, Math.floor(Date.now() / 1000));
  document.getElementById('tip').textContent = '第一层密文已生成（长度 ' + _e.length + '）';
} catch (e) {
  document.getElementById('tip').textContent = 'pack err: ' + e;
}
</script>
</body>
</html>
'''

DRIVER = u'''const fs = require('fs');
const O = require('javascript-obfuscator');
const src = fs.readFileSync(process.argv[2], 'utf8');
const res = O.obfuscate(src, {
  seed: 20280905,
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
    sys.exit('javascript-obfuscator not found')


def obfuscate():
    driver = os.path.join(ROOT, '.workbuddy', 'kl45_ob_run.js')
    out = os.path.join(ROOT, '.workbuddy', 'kl45_obf.js')
    os.makedirs(os.path.dirname(driver), exist_ok=True)
    io.open(driver, 'w', encoding='utf-8').write(DRIVER)
    env = dict(os.environ)
    env['NODE_PATH'] = find_obf()
    r = subprocess.run([find_node(), driver, PLAIN_JS, out], capture_output=True,
                       text=True, encoding='utf-8', errors='ignore', env=env)
    if r.returncode != 0:
        sys.exit('obfuscate failed:\n' + (r.stdout or '') + (r.stderr or ''))
    code = io.open(out, encoding='utf-8').read()
    print((r.stdout or '').strip())
    for f in (driver, out):
        if os.path.exists(f):
            os.remove(f)
    return code


def main():
    if not os.path.exists(PLAIN_JS):
        sys.exit('missing ' + PLAIN_JS)
    js = io.open(PLAIN_JS, encoding='utf-8').read()
    if '--no-obf' in sys.argv:
        print('obfuscation SKIPPED (--no-obf)')
    else:
        js = obfuscate()
    html = HTML.replace('//__FD_JS__', js)
    os.makedirs(os.path.dirname(OUT_HTML), exist_ok=True)
    io.open(OUT_HTML, 'w', encoding='utf-8').write(html)
    print('html bytes :', len(html.encode('utf-8')), '->', os.path.relpath(OUT_HTML, ROOT))


if __name__ == '__main__':
    main()
