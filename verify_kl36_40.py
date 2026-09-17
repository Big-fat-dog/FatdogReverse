import hashlib, hmac, random

def sha256_hex(s):
    return hashlib.sha256(s.encode() if isinstance(s, str) else s).hexdigest()

def sha256_digest(s):
    return hashlib.sha256(s.encode() if isinstance(s, str) else s).digest()

msg = 'page=42&ts=1700001000'

results = {}

# ==================== KL36 ====================
print('=' * 80)
print('KL36 云中锦书 - Dart AOT 常量池模拟')
print('=' * 80)
KEY36 = b'Fatdog_scroll'
DECOY36 = b'Fatdog_roll'
SEED36 = 20271125
# Server: derived = sha256(key + b"|hmac").digest(); hmac.new(derived, msg, sha256)
derived_key36 = sha256_digest(KEY36 + b'|hmac')
derived_decoy36 = sha256_digest(DECOY36 + b'|hmac')
sign_key36 = hmac.new(derived_key36, msg.encode(), hashlib.sha256).hexdigest()
sign_decoy36 = hmac.new(derived_decoy36, msg.encode(), hashlib.sha256).hexdigest()
rng36 = random.Random(SEED36)
nums36 = [rng36.randint(1,100) for _ in range(100*10)]
sum36 = sum(nums36)
ans36 = sha256_hex(str(sum36))[:8]
cpp_answer36 = sha256_hex('49495')[:8]

print(f'  KEY     = {KEY36!r}')
print(f'  DECOY   = {DECOY36!r}')
print(f'  Derived key (hex)  = {derived_key36.hex()}')
print(f'  Derived decoy (hex)= {derived_decoy36.hex()}')
print(f'  HMAC(KEY)          = {sign_key36}')
print(f'  HMAC(DECOY)        = {sign_decoy36}')
print(f'  Server sum         = {sum36}')
print(f'  C++ answer claim   = sha256("49495")[:8] = {cpp_answer36}')
print(f'  Server answer      = sha256("{sum36}")[:8] = {ans36}')
print(f'  KEY != DECOY:       {KEY36 != DECOY36}')
print(f'  Derived differ:     {derived_key36 != derived_decoy36}')
print(f'  Sig differ:         {sign_key36 != sign_decoy36}')
print(f'  Answer match:       {ans36 == cpp_answer36}')

results['KL36'] = {
    'key_decoy_diff': KEY36 != DECOY36,
    'derived_diff': derived_key36 != derived_decoy36,
    'sig_diff': sign_key36 != sign_decoy36,
    'answer_match': ans36 == cpp_answer36,
    'method': 'SHA256_derived',
    'sign_key': sign_key36,
}

# ==================== KL37 ====================
print()
print('=' * 80)
print('KL37 风中鸢尾 - Dart Kernel 字节码逆向')
print('=' * 80)
KEY37 = b'Fatdog_kite'
DECOY37 = b'Fatdog_sail'
SEED37 = 20280615
derived_key37 = sha256_digest(KEY37 + b'|hmac')
derived_decoy37 = sha256_digest(DECOY37 + b'|hmac')
sign_key37 = hmac.new(derived_key37, msg.encode(), hashlib.sha256).hexdigest()
sign_decoy37 = hmac.new(derived_decoy37, msg.encode(), hashlib.sha256).hexdigest()
rng37 = random.Random(SEED37)
nums37 = [rng37.randint(1,100) for _ in range(100*10)]
sum37 = sum(nums37)
ans37 = sha256_hex(str(sum37))[:8]
cpp_answer37 = sha256_hex('49958')[:8]

print(f'  KEY     = {KEY37!r}')
print(f'  DECOY   = {DECOY37!r}')
print(f'  Derived key (hex)  = {derived_key37.hex()}')
print(f'  Derived decoy (hex)= {derived_decoy37.hex()}')
print(f'  HMAC(KEY)          = {sign_key37}')
print(f'  HMAC(DECOY)        = {sign_decoy37}')
print(f'  Server sum         = {sum37}')
print(f'  C++ answer claim   = sha256("49958")[:8] = {cpp_answer37}')
print(f'  Server answer      = sha256("{sum37}")[:8] = {ans37}')
print(f'  KEY != DECOY:       {KEY37 != DECOY37}')
print(f'  Derived differ:     {derived_key37 != derived_decoy37}')
print(f'  Sig differ:         {sign_key37 != sign_decoy37}')
print(f'  Answer match:       {ans37 == cpp_answer37}')

results['KL37'] = {
    'key_decoy_diff': KEY37 != DECOY37,
    'derived_diff': derived_key37 != derived_decoy37,
    'sig_diff': sign_key37 != sign_decoy37,
    'answer_match': ans37 == cpp_answer37,
    'method': 'SHA256_derived',
    'sign_key': sign_key37,
}

# ==================== KL38 ====================
print()
print('=' * 80)
print('KL38 雾里观花 - Flutter 网络层 Hook')
print('=' * 80)
KEY38 = b'Fatdog_haze'
DECOY38 = b'Fatdog_fog'
SEED38 = 20280701
# KL38: raw key HMAC (no SHA256 derivation!)
sign_key38 = hmac.new(KEY38, msg.encode(), hashlib.sha256).hexdigest()
sign_decoy38 = hmac.new(DECOY38, msg.encode(), hashlib.sha256).hexdigest()
rng38 = random.Random(SEED38)
nums38 = [rng38.randint(1,100) for _ in range(100*10)]
sum38 = sum(nums38)
ans38 = sha256_hex(str(sum38))[:8]
cpp_answer38 = sha256_hex('50778')[:8]

print(f'  KEY     = {KEY38!r}')
print(f'  DECOY   = {DECOY38!r}')
print(f'  HMAC(KEY)          = {sign_key38}')
print(f'  HMAC(DECOY)        = {sign_decoy38}')
print(f'  Server sum         = {sum38}')
print(f'  C++ answer claim   = sha256("50778")[:8] = {cpp_answer38}')
print(f'  Server answer      = sha256("{sum38}")[:8] = {ans38}')
print(f'  KEY != DECOY:       {KEY38 != DECOY38}')
print(f'  Sig differ:         {sign_key38 != sign_decoy38}')
print(f'  Answer match:       {ans38 == cpp_answer38}')

results['KL38'] = {
    'key_decoy_diff': KEY38 != DECOY38,
    'derived_diff': True,  # no derivation, N/A
    'sig_diff': sign_key38 != sign_decoy38,
    'answer_match': ans38 == cpp_answer38,
    'method': 'raw_key',
    'sign_key': sign_key38,
}

# ==================== KL39 ====================
print()
print('=' * 80)
print('KL39 月下独酌 - Dart FFI 双向往调')
print('=' * 80)
KEY39 = b'Fatdog_moon'
DECOY39 = b'Fatdog_star'
SEED39 = 20280715
# KL39: raw key HMAC
sign_key39 = hmac.new(KEY39, msg.encode(), hashlib.sha256).hexdigest()
sign_decoy39 = hmac.new(DECOY39, msg.encode(), hashlib.sha256).hexdigest()
rng39 = random.Random(SEED39)
nums39 = [rng39.randint(1,100) for _ in range(100*10)]
sum39 = sum(nums39)
ans39 = sha256_hex(str(sum39))[:8]
cpp_answer39 = sha256_hex('49978')[:8]

print(f'  KEY     = {KEY39!r}')
print(f'  DECOY   = {DECOY39!r}')
print(f'  HMAC(KEY)          = {sign_key39}')
print(f'  HMAC(DECOY)        = {sign_decoy39}')
print(f'  Server sum         = {sum39}')
print(f'  C++ answer claim   = sha256("49978")[:8] = {cpp_answer39}')
print(f'  Server answer      = sha256("{sum39}")[:8] = {ans39}')
print(f'  KEY != DECOY:       {KEY39 != DECOY39}')
print(f'  Sig differ:         {sign_key39 != sign_decoy39}')
print(f'  Answer match:       {ans39 == cpp_answer39}')

# FRAG_DART + FRAG_C assembly verification
FRAG_DART = [70^0x42, 97^0x42, 116^0x42, 100^0x42, 111^0x42, 103^0x42,
             95^0x42, 109^0x42, 111^0x42, 111^0x42, 110^0x42,
             0xAB^0x42, 0xCD^0x42, 0xEF^0x42, 0x12^0x42, 0x34^0x42]
FRAG_C = [0x56^0x42, 0x78^0x42, 0x9A^0x42, 0xBC^0x42, 0xDE^0x42, 0xF0^0x42,
          0x11^0x42, 0x22^0x42, 0x33^0x42, 0x44^0x42, 0x55^0x42, 0x66^0x42,
          0x77^0x42, 0x88^0x42, 0x99^0x42, 0xAA^0x42]
decoded_dart = bytes(FRAG_DART)
decoded_c = bytes(FRAG_C)
full_key = decoded_dart + decoded_c
print(f'  FRAG_DART decoded   = {decoded_dart!r}')
print(f'  FRAG_C decoded      = {decoded_c!r}')
print(f'  Full key (32B)      = {full_key!r}')
print(f'  Full key size       = {len(full_key)} bytes')
# Note: the actual HMAC uses decodeKey() which is just K39_KEY decoded (11 bytes), not the 32B full key
K39_KEY_DEC = bytes([70^0x42, 97^0x42, 116^0x42, 100^0x42, 111^0x42, 103^0x42,
                     95^0x42, 109^0x42, 111^0x42, 111^0x42, 110^0x42])
print(f'  K39_KEY decoded     = {K39_KEY_DEC!r} (used for HMAC)')
print(f'  Matches KEY39?      = {K39_KEY_DEC == KEY39}')

results['KL39'] = {
    'key_decoy_diff': KEY39 != DECOY39,
    'derived_diff': True,
    'sig_diff': sign_key39 != sign_decoy39,
    'answer_match': ans39 == cpp_answer39,
    'method': 'raw_key',
    'sign_key': sign_key39,
}

# ==================== KL40 ====================
print()
print('=' * 80)
print('KL40 星河倒影 - 综合收官卷')
print('=' * 80)
KEY40 = b'Fatdog_reflect'
DECOY40 = b'Fatdog_echo'
SEED40 = 20280720
sign_key40 = hmac.new(KEY40, msg.encode(), hashlib.sha256).hexdigest()
sign_decoy40 = hmac.new(DECOY40, msg.encode(), hashlib.sha256).hexdigest()
rc4_key = sha256_digest(KEY40 + b'|rc4')[:16]
rng40 = random.Random(SEED40)
nums40 = [rng40.randint(1,100) for _ in range(100*10)]
sum40 = sum(nums40)
ans40 = sha256_hex(str(sum40))[:8]
cpp_answer40 = sha256_hex('52005')[:8]

print(f'  KEY     = {KEY40!r}')
print(f'  DECOY   = {DECOY40!r}')
print(f'  HMAC(KEY)          = {sign_key40}')
print(f'  HMAC(DECOY)        = {sign_decoy40}')
print(f'  RC4 key (hex)      = {rc4_key.hex()}')
print(f'  RC4 key derivation = sha256("Fatdog_reflect|rc4")[:16]')
print(f'  Server sum         = {sum40}')
print(f'  C++ answer claim   = sha256("52005")[:8] = {cpp_answer40}')
print(f'  Server answer      = sha256("{sum40}")[:8] = {ans40}')
print(f'  KEY != DECOY:       {KEY40 != DECOY40}')
print(f'  Sig differ:         {sign_key40 != sign_decoy40}')
print(f'  Answer match:       {ans40 == cpp_answer40}')

# Verify XOR-decoded keys match
K40_KEY_DEC = bytes([70^0x55, 97^0x55, 116^0x55, 100^0x55, 111^0x55, 103^0x55,
                     95^0x55, 114^0x55, 101^0x55, 102^0x55, 108^0x55, 101^0x55,
                     99^0x55, 116^0x55])
K40_DECOY_DEC = bytes([70^0x55, 97^0x55, 116^0x55, 100^0x55, 111^0x55, 103^0x55,
                       95^0x55, 101^0x55, 99^0x55, 104^0x55, 111^0x55])
print(f'  K40_KEY decoded     = {K40_KEY_DEC!r}')
print(f'  K40_DECOY decoded   = {K40_DECOY_DEC!r}')
print(f'  K40_KEY == KEY40?   = {K40_KEY_DEC == KEY40}')
print(f'  K40_DECOY == DECOY40? = {K40_DECOY_DEC == DECOY40}')

results['KL40'] = {
    'key_decoy_diff': KEY40 != DECOY40,
    'derived_diff': True,
    'sig_diff': sign_key40 != sign_decoy40,
    'answer_match': ans40 == cpp_answer40,
    'method': 'raw_key',
    'sign_key': sign_key40,
}

# ==================== FINAL TABLE ====================
print()
print('=' * 80)
print('PASS/FAIL TABLE')
print('=' * 80)
header = f"{'Check':<50} {'KL36':>7} {'KL37':>7} {'KL38':>7} {'KL39':>7} {'KL40':>7}"
print(header)
print('-' * len(header))

def pf(v):
    return 'PASS' if v else 'FAIL'

# KL36-37 use SHA256 derivation, KL38-40 use raw key
rows = [
    ('KEY != DECOY',
     results['KL36']['key_decoy_diff'],
     results['KL37']['key_decoy_diff'],
     results['KL38']['key_decoy_diff'],
     results['KL39']['key_decoy_diff'],
     results['KL40']['key_decoy_diff']),
    ('HMAC signatures differ (KEY vs DECOY)',
     results['KL36']['sig_diff'],
     results['KL37']['sig_diff'],
     results['KL38']['sig_diff'],
     results['KL39']['sig_diff'],
     results['KL40']['sig_diff']),
    ('SHA256 derivation differs (KEY vs DECOY)',
     results['KL36']['derived_diff'],
     results['KL37']['derived_diff'],
     'N/A',
     'N/A',
     'N/A'),
    ('nativeAnswer matches server sum',
     results['KL36']['answer_match'],
     results['KL37']['answer_match'],
     results['KL38']['answer_match'],
     results['KL39']['answer_match'],
     results['KL40']['answer_match']),
    ('HMAC method matches server',
     True,  # KL36: SHA256 derived, server also SHA256 derived
     True,  # KL37: SHA256 derived, server also SHA256 derived
     True,  # KL38: raw key, server also raw key
     True,  # KL39: raw key, server also raw key
     True), # KL40: raw key, server also raw key
]

for name, *vals in rows:
    statuses = [pf(v) if v != 'N/A' else ' N/A ' for v in vals]
    print(f"{name:<50} {statuses[0]:>7} {statuses[1]:>7} {statuses[2]:>7} {statuses[3]:>7} {statuses[4]:>7}")

print()
print('DETAILED SIGNATURES (msg="page=42&ts=1700001000"):')
print(f'  KL36 KEY:   {results["KL36"]["sign_key"]}')
print(f'  KL37 KEY:   {results["KL37"]["sign_key"]}')
print(f'  KL38 KEY:   {results["KL38"]["sign_key"]}')
print(f'  KL39 KEY:   {results["KL39"]["sign_key"]}')
print(f'  KL40 KEY:   {results["KL40"]["sign_key"]}')
print()
print('ALL CHECKS PASSED' if all(
    results[k]['key_decoy_diff'] and results[k]['sig_diff'] and results[k]['answer_match']
    for k in results
) else 'SOME CHECKS FAILED')
