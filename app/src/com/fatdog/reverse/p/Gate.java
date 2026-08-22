package com.fatdog.reverse.p;

import com.fatdog.reverse.NetHost;
import com.fatdog.reverse.Tm;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;

// 关卡 27 的 TLS 客户端：TrustManager（信内置 CA，复用 Tm.caDer()）+ CertificatePinner 双闸门。
// pin 没有明文（^0x27 数组在 Mk，运行时还原）——mitmproxy 要同时放倒两道闸才能看到明文。
public class Gate {
    private static OkHttpClient client;

    static OkHttpClient get() throws Exception {
        if (client != null) {
            return client;
        }
        synchronized (Gate.class) {
            if (client != null) {
                return client;
            }
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate ca = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(Tm.caDer()));
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            ks.setCertificateEntry("fatdemo", ca);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, tmf.getTrustManagers(), new SecureRandom());

            final String host = NetHost.host();
            HostnameVerifier hv = new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return host.equals(hostname);
                }
            };
            CertificatePinner pinner = new CertificatePinner.Builder()
                    .add(host, Mk.pin())
                    .build();

            client = new OkHttpClient.Builder()
                    .sslSocketFactory(sc.getSocketFactory(), (X509TrustManager) tmf.getTrustManagers()[0])
                    .hostnameVerifier(hv)
                    .certificatePinner(pinner)
                    .connectTimeout(5, TimeUnit.SECONDS)
                    .readTimeout(5, TimeUnit.SECONDS)
                    .build();
            return client;
        }
    }
}
