# -*- coding: utf-8 -*-
"""生成关卡 21+ 用的本地 TLS 证书：自签 CA + 由其签发的服务器证书。

用法：python gen_certs.py   生成 certs/{ca.crt,ca.key,server.crt,server.key}
                        + certs/{client.crt,client.key,client.p12}（关卡 26 mTLS 用）
服务器证书 SAN 包含 localhost / 127.0.0.1 / 10.0.2.2（模拟器宿主机）。
客户端证书由同一 CA 签发（CN=fatdog-client，EKU=clientAuth），
PKCS12 导出密码 fatdemo_mt26，并复制一份到 app/assets/mt_client.p12 进 APK。
"""
import datetime
import os
import shutil
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
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
    p12 = pkcs12.serialize_key_and_certificates(
        name=b"fatdog-client", key=cl_key, cert=cl, cas=[ca],
        encryption_algorithm=serialization.BestAvailableEncryption(CLIENT_P12_PASS))
    write("client.p12", p12)
    dst = os.path.join(HERE, "app", "assets", "mt_client.p12")
    shutil.copyfile(os.path.join(OUT, "client.p12"), dst)
    print("复制 -> app/assets/mt_client.p12")

    # 顺带把 CA 的 DER 打出来（App 端嵌入/字符串加密用）
    der = ca.public_bytes(serialization.Encoding.DER)
    print("CA DER 长度:", len(der))


if __name__ == "__main__":
    main()