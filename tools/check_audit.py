import re, os

def read(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()

results = []

# 1. LEVEL_IDS/NAMES/DESCS equal length
c = read('app/src/com/fatdog/reverse/DivineReflectionActivity.java')
ids = re.findall(r'LEVEL_IDS\s*=\s*\{(.*?)\};', c, re.DOTALL)
names = re.findall(r'private static final String\[\] NAMES\s*=\s*\{(.*?)\};', c, re.DOTALL)
descs = re.findall(r'private static final String\[\] DESCS\s*=\s*\{(.*?)\};', c, re.DOTALL)
id_count = len(re.findall(r'"[A-Z][A-Z0-9]+"', ids[0])) if ids else 0
name_count = len(re.findall(r'"[^"]+"', names[0])) if names else 0
desc_count = len(re.findall(r'"[^"]+"', descs[0])) if descs else 0
ok = id_count == name_count == desc_count == 94
results.append(('1. LEVEL_IDS/NAMES/DESCS equal (94)', ok, f'ids={id_count} names={name_count} descs={desc_count}'))

# 2. TOTAL_LEVELS
c = read('app/src/com/fatdog/reverse/ProfileActivity.java')
m = re.search(r'TOTAL_LEVELS\s*=\s*(\d+)', c)
ok = m and m.group(1) == '94'
results.append(('2. TOTAL_LEVELS=94', ok, m.group(1) if m else 'NOT FOUND'))

# 3. MainActivity kunlunCat==7 + tacticActivity
c = read('app/src/com/fatdog/reverse/MainActivity.java')
ok = 'kunlunCat == 7' in c and 'tacticActivity.class' in c
results.append(('3. MainActivity kunlunCat==7', ok, ''))

# 4. ProfileActivity 须弥界 zone
c = read('app/src/com/fatdog/reverse/ProfileActivity.java')
ok = '须弥界' in c and 'tacticActivity' in c
results.append(('4. ProfileActivity须弥界', ok, ''))

# 5. AndroidManifest
c = read('app/AndroidManifest.xml')
ok = '.tacticActivity' in c
results.append(('5. Manifest tacticActivity', ok, ''))

# 6. Banner unique
has_kl41 = os.path.exists('app/res/drawable-nodpi/level_kl41.jpg')
results.append(('6. Banner level_kl41.jpg', has_kl41, ''))

# 7. loadLibrary matches SO name
c = read('app/src/com/fatdog/reverse/RnBridge.java')
c2 = read('app/jni/Android.mk')
ok = 'loadLibrary("fox")' in c and 'LOCAL_MODULE := fox' in c2
results.append(('7. loadLibrary=fox=Android.mk', ok, ''))

# 8. JNI signatures
c = read('app/jni/kl41.cpp')
ok = 'JNI_OnLoad' in c and 'nativeSign' in c and 'JNIEXPORT' in c
results.append(('8. JNI_OnLoad+nativeSign', ok, ''))

# 9. server.py route
c = read('server.py')
ok = '/api/kl41' in c and 'Fatdog_tactic' in c
results.append(('9. server.py /api/kl41', ok, ''))

# 10. No plaintext key in Java code
found = False
for root, dirs, files in os.walk('app/src'):
    for fn in files:
        if fn.endswith('.java'):
            path = os.path.join(root, fn)
            content = read(path)
            for line in content.split('\n'):
                stripped = line.strip()
                if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*'):
                    continue
                if 'Fatdog_tactic' in stripped:
                    found = True
results.append(('10. No plaintext key in Java', not found, ''))

# 11. No hint leaks
c = read('app/src/com/fatdog/reverse/tacticActivity.java')
hint_idx = c.find('hint')
if hint_idx > 0:
    hint_section = c[hint_idx:]
    bad = '0x3C' in hint_section or 'HmacSHA256' in hint_section
else:
    bad = False
results.append(('11. No hint leaks', not bad, ''))

# 12. UI template
ok = 'wrapScroll' in c and 'Ui.banner' in c and 'ScrollView' not in c.split('wrapScroll')[0][-200:]
results.append(('12. UI template', ok, ''))

# Print results
all_pass = True
for name, ok, detail in results:
    status = 'PASS' if ok else 'FAIL'
    if not ok: all_pass = False
    line = f'  {status} {name}'
    if detail: line += f' ({detail})'
    print(line)

print()
if all_pass:
    print('ALL 12 ITEMS PASS')
else:
    print('SOME ITEMS FAILED')
