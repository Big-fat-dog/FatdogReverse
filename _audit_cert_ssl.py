import subprocess, base64, hashlib, sys, os

ROOT = r"D:\大胖狗的学习\FatdogReverse"
CERTS = os.path.join(ROOT, "certs")
ASSETS = os.path.join(ROOT, "app", "assets")

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True).stdout

def spki_pin(crt_path):
    # get pubkey DER then sha256 base64
    pub = subprocess.run(f'openssl x509 -in "{crt_path}" -noout -pubkey', shell=True, capture_output=True).stdout
    der = subprocess.run('openssl pkey -pubin -outform DER', shell=True, input=pub, capture_output=True).stdout
    d = hashlib.sha256(der).digest()
    return "sha256/" + base64.b64encode(d).decode()

def ca_der(crt_path):
    return subprocess.run(f'openssl x509 -in "{crt_path}" -outform DER', shell=True, capture_output=True).stdout

print("=== server.crt SPKI pin ===")
srv_pin = spki_pin(os.path.join(CERTS, "server.crt"))
print("server SPKI:", srv_pin)

print("\n=== A. 三处 SPKI pin 比对 ===")
# Pn.PIN literal
pn_pin = "sha256/B3Mk7KMT2PA+BI0tXRk8t8lNdgMYIo70qvZ59BzGpR4="
print("Pn.PIN      :", pn_pin, "-> MATCH" if pn_pin == srv_pin else "-> MISMATCH")

# Z24Core.PINX ^0x5A
PINX = [41, 50, 59, 104, 111, 108, 117, 24, 105, 23, 49, 109, 17, 23, 14, 104, 10, 27, 113, 24, 19, 106, 46, 2, 8, 49, 98, 46, 98, 54, 20, 62, 61, 23, 3, 19, 53, 109, 106, 43, 44, 0, 111, 99, 24, 32, 29, 42, 8, 110, 103]
z24 = "".join(chr(b ^ 0x5A) for b in PINX)
print("Z24Core.PINX:", z24, "-> MATCH" if z24 == srv_pin else "-> MISMATCH")

# p/Mk.S_PIN ^0x27 (无 sha256/ 前缀)
S_PIN = [84, 79, 70, 21, 18, 17, 8, 101, 20, 106, 76, 16, 108, 106, 115, 21, 119, 102, 12, 101, 110, 23, 83, 127, 117, 76, 31, 83, 31, 75, 105, 67, 64, 106, 126, 110, 72, 16, 23, 86, 81, 125, 18, 30, 101, 93, 96, 87, 117, 19, 26]
mk_pin = "".join(chr(b ^ 0x27) for b in S_PIN)
print("Mk.S_PIN(dec):", mk_pin, "(prefix added ->", "sha256/"+mk_pin + ")")
print("Mk.S_PIN+pref :", "sha256/"+mk_pin, "-> MATCH" if "sha256/"+mk_pin == srv_pin else "-> MISMATCH")

print("\n=== B. 内嵌 CA (Tm.CAA ^0x5A) vs certs/ca.crt ===")
CAA = [106, 216, 88, 189, 106, 216, 91, 149, 250, 89, 88, 91, 88, 88, 78, 125, 242, 25, 153, 154, 137, 226, 188, 70, 203, 140, 80, 186, 213, 150, 231, 82, 122, 253, 218, 106, 87, 92, 83, 112, 220, 18, 220, 173, 87, 91, 91, 81, 95, 90, 106, 121, 107, 123, 106, 69, 92, 89, 15, 94, 89, 86, 66, 178, 217, 204, 189, 209, 205, 122, 28, 59, 46, 62, 63, 55, 53, 122, 188, 239, 209, 178, 245, 207, 122, 25, 27, 106, 68, 77, 87, 104, 108, 106, 98, 104, 106, 107, 105, 111, 108, 105, 105, 0, 77, 87, 105, 108, 106, 98, 107, 98, 107, 105, 111, 108, 105, 105, 0, 106, 121, 107, 123, 106, 69, 92, 89, 15, 94, 89, 86, 66, 178, 217, 204, 189, 209, 205, 122, 28, 59, 46, 62, 63, 55, 53, 122, 188, 239, 209, 178, 245, 207, 122, 25, 27, 106, 216, 91, 120, 106, 87, 92, 83, 112, 220, 18, 220, 173, 87, 91, 91, 91, 95, 90, 89, 216, 91, 85, 90, 106, 216, 91, 80, 88, 216, 91, 91, 90, 150, 103, 78, 102, 56, 221, 241, 179, 109, 127, 8, 193, 67, 234, 227, 216, 18, 108, 211, 115, 81, 62, 6, 181, 173, 238, 240, 229, 210, 144, 10, 221, 253, 128, 176, 49, 57, 239, 207, 15, 12, 0, 211, 43, 130, 189, 104, 42, 9, 253, 130, 187, 181, 252, 199, 110, 127, 215, 137, 233, 59, 120, 28, 131, 198, 51, 62, 86, 208, 155, 233, 10, 19, 186, 176, 173, 201, 4, 172, 171, 22, 97, 145, 54, 0, 244, 216, 95, 63, 164, 6, 131, 41, 224, 254, 60, 165, 20, 3, 208, 49, 187, 240, 96, 13, 18, 59, 199, 83, 174, 131, 102, 180, 158, 9, 42, 237, 125, 165, 21, 122, 172, 93, 242, 36, 6, 60, 165, 94, 36, 2, 109, 242, 76, 213, 7, 127, 171, 235, 184, 95, 103, 69, 143, 24, 252, 177, 159, 169, 57, 144, 85, 150, 98, 146, 43, 210, 234, 73, 232, 36, 188, 189, 157, 75, 176, 233, 153, 85, 24, 250, 135, 60, 127, 201, 155, 43, 247, 144, 18, 179, 171, 14, 51, 131, 125, 149, 234, 107, 104, 117, 43, 67, 1, 103, 223, 30, 235, 29, 49, 102, 140, 137, 221, 112, 168, 140, 136, 150, 43, 105, 170, 7, 182, 63, 195, 84, 194, 222, 7, 155, 212, 89, 194, 239, 68, 245, 71, 148, 139, 148, 249, 68, 179, 137, 218, 71, 2, 20, 70, 57, 174, 227, 221, 30, 134, 85, 254, 240, 230, 155, 57, 39, 27, 92, 5, 88, 89, 91, 90, 91, 249, 73, 106, 75, 106, 85, 92, 89, 15, 71, 73, 91, 91, 165, 94, 95, 106, 89, 91, 91, 165, 106, 87, 92, 83, 112, 220, 18, 220, 173, 87, 91, 91, 81, 95, 90, 89, 216, 91, 91, 90, 73, 109, 145, 70, 2, 97, 68, 126, 225, 71, 139, 102, 115, 163, 91, 103, 9, 208, 147, 26, 15, 86, 12, 175, 224, 137, 245, 222, 127, 65, 75, 180, 73, 138, 41, 18, 6, 22, 213, 154, 120, 175, 84, 91, 165, 50, 254, 230, 52, 217, 124, 208, 198, 185, 254, 224, 113, 92, 208, 179, 47, 14, 92, 233, 59, 67, 143, 47, 230, 49, 151, 72, 148, 224, 222, 31, 108, 243, 61, 135, 47, 125, 127, 203, 149, 45, 68, 226, 151, 20, 176, 194, 139, 151, 18, 129, 170, 43, 188, 11, 70, 185, 255, 45, 210, 44, 255, 141, 24, 242, 106, 109, 66, 180, 255, 134, 199, 122, 26, 232, 154, 45, 67, 244, 2, 17, 71, 90, 23, 55, 194, 57, 85, 229, 43, 203, 8, 91, 123, 74, 32, 112, 190, 125, 100, 96, 7, 117, 10, 153, 146, 74, 38, 25, 13, 83, 58, 44, 231, 248, 154, 210, 197, 74, 213, 107, 216, 178, 230, 233, 58, 8, 126, 113, 191, 149, 232, 171, 151, 190, 96, 94, 172, 50, 139, 63, 29, 223, 231, 80, 91, 17, 99, 226, 59, 61, 193, 71, 153, 209, 23, 127, 157, 180, 61, 211, 170, 36, 99, 226, 239, 83, 39, 59, 196, 201, 18, 105, 127, 18, 189, 221, 21, 252, 104, 226, 24, 104, 24, 121, 33, 244, 75, 229, 91, 220, 19, 241, 2, 108, 80, 116, 131, 22, 107, 71, 253, 178, 53, 164, 18, 110, 76, 136, 77, 28]
ca_dec = bytes(b ^ 0x5A for b in CAA)
ca_real = ca_der(os.path.join(CERTS, "ca.crt"))
print("CAA len:", len(ca_dec), "ca.crt DER len:", len(ca_real))
print("CAA == ca.crt DER:", ca_dec == ca_real)

print("\n=== C. mTLS p12 比对 + 口令 ===")
ap = os.path.join(ASSETS, "mt_client.p12")
cp = os.path.join(CERTS, "client.p12")
with open(ap, "rb") as f: a = f.read()
with open(cp, "rb") as f: c = f.read()
print("mt_client.p12 bytes == certs/client.p12:", a == c, f"({len(a)} vs {len(c)})")
# 口令
pw = "fatdemo_mt26"
r = subprocess.run(f'openssl pkcs12 -in "{cp}" -info -nokeys -passin pass:{pw} -nomacver', shell=True, capture_output=True)
print("open client.p12 with 'fatdemo_mt26':", "OK" if b"friendlyName" in r.stdout or b"BEGIN CERT" in r.stdout else "FAIL")
if r.returncode != 0:
    print("  stderr:", r.stderr[:200])
# 也测 assets 里的
r2 = subprocess.run(f'openssl pkcs12 -in "{ap}" -info -nokeys -passin pass:{pw} -nomacver', shell=True, capture_output=True)
print("open assets/mt_client.p12 with 'fatdemo_mt26':", "OK" if (b"friendlyName" in r2.stdout or b"BEGIN CERT" in r2.stdout) else "FAIL")
