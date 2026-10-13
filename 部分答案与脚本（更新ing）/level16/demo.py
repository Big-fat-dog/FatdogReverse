import hashlib, json, time, urllib.request

def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):                      # KSA：用密钥打乱 S 盒
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:                            # PRGA：边搅边吐密钥流
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xff])
    return bytes(out)

REQ_KEY = b'fatdemo_rc4_req_2026'
RSP_KEY = b'fatdemo_rc4_rsp_2026'
SALT    = b'fatdemo_rc4_sig_salt'

def fetch(page):
    ts = int(time.time())
    plain = ('page=%d&ts=%d' % (page, ts)).encode()
    payload = rc4(REQ_KEY, plain).hex()
    sig = hashlib.md5((payload + SALT.decode()).encode()).hexdigest()
    url = 'http://127.0.0.1:8787/api/rc4?payload=%s&sig=%s' % (payload, sig)
    with urllib.request.urlopen(url) as r:
        obj = json.loads(r.read())
        print(obj)
    clear = rc4(RSP_KEY, bytes.fromhex(obj['d'])).decode()
    nums = [int(x) for x in clear.split('|')[1].split('=')[1].split(',')]
    return nums

total = 0
for p in range(1, 61):
    total += sum(fetch(p))
print(total)          # 24074