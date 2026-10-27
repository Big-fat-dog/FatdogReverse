# -*- coding: utf-8 -*-
"""L43-L47「签名校验对抗」协议字段一致性自检。

干什么
------
把 server.py 里 `/api/l43` … `/api/l47` 的**必填参数**（Query/Form）
和客户端实际发出去的**字段集合**逐关对拍，缺字段/多字段都报错。

为什么需要
----------
FastAPI 的必填字段一旦漏发，返回的是 **422 ValidationError**，不是 403：

    {"detail":[{"type":"missing","loc":["body","vt"],"msg":"Field required"}]}

它看起来像"服务端 bug"，其实是客户端少塞了一个字段（L47 `Zd.java` 就漏过 `vt`，
导致这一关原包也取不到数）。这类错误 javac 完全不管，只能靠静态对拍或真机联调发现。

用法
----
    python tools/verify_l43_l47_protocol.py

退出码 0 = 五关字段完全对齐；1 = 有缺/多字段（会打印是哪一关、哪个字段）。
"""
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(HERE, 'app', 'src', 'com', 'fatdog', 'reverse')
SERVER = os.path.join(HERE, 'server.py')

# 关卡 → 客户端类（L43-L45 走 GET query，L46/L47 走 POST form）
CLIENTS = {
    43: 'Vk.java',
    44: 'Xh.java',
    45: 'Yb.java',
    46: 'Zc.java',
    47: 'Zd.java',
}

RESULTS = []


def check(level, miss, extra):
    ok = not miss and not extra
    RESULTS.append(ok)
    detail = []
    if miss:
        detail.append('缺少 ' + ', '.join(sorted(miss)))
    if extra:
        detail.append('多出 ' + ', '.join(sorted(extra)))
    print('  [%s] L%d %-10s %s' % ('PASS' if ok else 'FAIL', level,
                                   CLIENTS[level], '、'.join(detail) or '字段齐全'))
    return ok


def server_params(level):
    s = io.open(SERVER, encoding='utf-8').read()
    m = re.search(r'def api_l%d\((.*?)\):' % level, s, re.S)
    if not m:
        return None
    return set(re.findall(r'(\w+)\s*:\s*\w+\s*=\s*(?:Query|Form)\(', m.group(1)))


def client_fields(fname):
    s = io.open(os.path.join(SRC, fname), encoding='utf-8').read()
    fields = set(re.findall(r'\.add\("(\w+)"', s))          # FormBody.add("x", ...)
    fields |= set(re.findall(r'[?&](\w+)="\s*\+', s))       # "?page=" + page / "&vt=" + vt
    return fields


def main():
    print('L43-L47 客户端字段 vs server.py 必填参数：')
    for lv in sorted(CLIENTS):
        sp = server_params(lv)
        if sp is None:
            check(lv, {'（server.py 里找不到 api_l%d）' % lv}, set())
            continue
        cf = client_fields(CLIENTS[lv])
        check(lv, sp - cf, cf - sp)

    print()
    if all(RESULTS):
        print('五关协议字段完全一致（ALL PASS）')
        return 0
    print('有 %d 关字段不一致：缺字段会让服务端直接回 422 ValidationError'
          '（不是 403），客户端看起来像"服务端坏了"。' % RESULTS.count(False))
    return 1


if __name__ == '__main__':
    sys.exit(main())
