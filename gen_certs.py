# -*- coding: utf-8 -*-
"""生成关卡 21+ 用的本地 TLS 证书：自签 CA + 由其签发的服务器证书。

用法：python gen_certs.py   生成 certs/{ca.crt,ca.key,server.crt,server.key}
服务器证书 SAN 包含 localhost / 127.0.0.1 / 10.0.2.2（模拟器宿主机）。
"""
import datetime
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "certs")
os.makedirs(OUT, exist_ok=True)

now = datetime.datetime.utcnow()


def write(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)
    print("写出 certs/" + name)


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

    # 顺带把 CA 的 DER 打出来（App 端嵌入/字符串加密用）
    der = ca.public_bytes(serialization.Encoding.DER)
    print("CA DER 长度:", len(der))


if __name__ == "__main__":
    main()