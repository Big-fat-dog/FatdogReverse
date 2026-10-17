# -*- coding: utf-8 -*-
"""生成关卡 21+ 用的本地 TLS 证书：自签 CA + 由其签发的服务器证书。

用法：python gen_certs.py   生成 certs/{ca.crt,ca.key,server.crt,server.key}
                        + certs/{client.crt,client.key,client.p12}（关卡 26 mTLS 用）
服务器证书 SAN 包含 localhost / 127.0.0.1 / 10.0.2.2（模拟器宿主机）。
客户端证书由同一 CA 签发（CN=fatdog-client，EKU=clientAuth），
PKCS12 导出密码 fatdemo_mt26，并复制一份到 app/assets/mt_client.p12 进 APK。

★ 坑（2026-10-17 真机实测）：p12 必须用 legacy PBE（PBE-SHA1-3DES + HmacPBESHA1）导出。
Android 的 PKCS12 KeyStore（BouncyCastle）不支持 PBES2/PBKDF2/AES，
cryptography 的 BestAvailableEncryption 会写成 PBES2，App 里 KeyStore.load() 直接抛
"NoSuchAlgorithmException: 1.2.840.113549.1.5.12 SecretKeyFactory not available"，
表现为第 26 关一进页面就「请求失败」，连 TLS 握手都发不出去。
"""
import datetime
import os
import shutil
import subprocess
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "certs")
os.makedirs(OUT, exist_ok=True)

# 关卡 26：客户端证书 PKCS12 的导出密码（App 里以 XOR 数组拆分藏着）
CLIENT_P12_PASS = b"fatdemo_mt26"

now = datetime.datetime.utcnow()


def write(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)
    print("写出 certs/" + name)


def find_openssl():
    """找 openssl：PATH 优先，其次 Git for Windows 的常见安装位置。"""
    p = shutil.which("openssl")
    if p:
        return p
    for c in (r"C:\Program Files\Git\usr\bin\openssl.exe",
              r"C:\Program Files\Git\mingw64\bin\openssl.exe",
              r"C:\Program Files (x86)\Git\usr\bin\openssl.exe"):
        if os.path.exists(c):
            return c
    return None


def export_legacy_p12(crt, key, ca, out, password, alias="fatdog-client"):
    """用 legacy PBE 导出 p12，Android 才解得开（详见文件头部的坑）。"""
    openssl = find_openssl()
    if not openssl:
        raise RuntimeError(
            "找不到 openssl：Android 端 p12 必须用 legacy PBE 导出。"
            "请安装 OpenSSL，或把 Git 的 usr/bin 加进 PATH 后重跑。")
    cmd = [openssl, "pkcs12", "-export",
           "-in", crt, "-inkey", key, "-certfile", ca,
           "-name", alias,
           "-keypbe", "PBE-SHA1-3DES",
           "-certpbe", "PBE-SHA1-3DES",
           "-macalg", "sha1",
           "-iter", "2048",
           "-out", out,
           "-passout", "pass:" + password]
    subprocess.run(cmd, check=True)
    print("写出 " + out + "（legacy PBE-SHA1-3DES）")


def main():
    # ---- CA ----
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "胖狗 Fatdemo 测试 CA")])
    ca = (x509.CertificateBuilder()
          .subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    write("ca.crt", ca.public_bytes(serialization.Encoding.PEM))
    write("ca.key", ca_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))

    # ---- 服务器证书（SAN 覆盖本机 + 模拟器宿主机） ----
    sv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sv_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    sv = (x509.CertificateBuilder()
          .subject_name(sv_name).issuer_name(ca_name)
          .public_key(sv_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=825))
          .add_extension(x509.SubjectAlternativeName([
              x509.DNSName("localhost"),
              x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
              x509.IPAddress(__import__("ipaddress").ip_address("10.0.2.2")),
          ]), critical=False)
          .sign(ca_key, hashes.SHA256()))
    write("server.crt", sv.public_bytes(serialization.Encoding.PEM))
    write("server.key", sv_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))

    # ---- 客户端证书（关卡 26 mTLS：服务端要求出示客户端证书） ----
    cl_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cl_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fatdog-client")])
    cl = (x509.CertificateBuilder()
          .subject_name(cl_name).issuer_name(ca_name)
          .public_key(cl_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=825))
          .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
          .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                         critical=False)
          .sign(ca_key, hashes.SHA256()))
    write("client.crt", cl.public_bytes(serialization.Encoding.PEM))
    write("client.key", cl_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    export_legacy_p12(os.path.join(OUT, "client.crt"),
                      os.path.join(OUT, "client.key"),
                      os.path.join(OUT, "ca.crt"),
                      os.path.join(OUT, "client.p12"),
                      CLIENT_P12_PASS.decode())
    dst = os.path.join(HERE, "app", "assets", "mt_client.p12")
    shutil.copyfile(os.path.join(OUT, "client.p12"), dst)
    print("复制 -> app/assets/mt_client.p12")

    # 顺带把 CA 的 DER 打出来（App 端嵌入/字符串加密用）
    der = ca.public_bytes(serialization.Encoding.DER)
    print("CA DER 长度:", len(der))


if __name__ == "__main__":
    main()