import re
with open('app/src/com/fatdog/reverse/DivineReflectionActivity.java', 'r', encoding='utf-8') as f:
    c = f.read()

ids = re.findall(r'LEVEL_IDS\s*=\s*\{(.*?)\};', c, re.DOTALL)
names = re.findall(r'private static final String\[\] NAMES\s*=\s*\{(.*?)\};', c, re.DOTALL)
descs = re.findall(r'private static final String\[\] DESCS\s*=\s*\{(.*?)\};', c, re.DOTALL)

id_count = len(re.findall(r'"[A-Z][A-Z0-9]+"', ids[0])) if ids else 0
name_count = len(re.findall(r'"[^"]+"', names[0])) if names else 0
desc_count = len(re.findall(r'"[^"]+"', descs[0])) if descs else 0

print(f'LEVEL_IDS: {id_count}, NAMES: {name_count}, DESCS: {desc_count}')
if id_count == name_count == desc_count:
    print('PASS')
else:
    print('FAIL')
