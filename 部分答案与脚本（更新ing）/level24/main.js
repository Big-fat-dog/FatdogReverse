// Java.perform(function () {
//     //先过证书信任
//     var SSLContext = Java.use("javax.net.ssl.SSLContext");
//     var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
//
//     var MyTrustManager = Java.registerClass({
//         name: 'com.fatdog.reverse.TrustBypass',
//         implements: [X509TrustManager],
//         methods: {
//             checkClientTrusted: function () {
//             },
//             checkServerTrusted: function () {
//             },
//             getAcceptedIssuers: function () {
//                 return [];
//             }
//         }
//     })
//
//
//     var tm = MyTrustManager.$new();
//
//     SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (km, oldTm, random) {
//
//         console.log("[+] SSLContext.init() intercepted");
//
//         var newTm = Java.array(
//             "javax.net.ssl.TrustManager",
//             [tm]
//         );
//
//         console.log("[+] Replacing TrustManager");
//
//         return this.init(km, newTm, random);
//     };
//
//     console.log("[+] Hook installed");
//
//
//     //小坑，这里是个接口，实现了匿名类。HostnameVerifier hostnameVerifier = new HostnameVerifier() { // from class: com.fatdog.reverse.Pn.1
//     //这里我们直接修改掉这个类的verify方法
//
//
//     var verifier = Java.use("com.fatdog.reverse.Pn$1");//匿名类哦
//     verifier.verify.implementation = function (str, session) {
//         console.log("[+] verifier.verify.implementation(str,session);")
//         return true
//     }
//
//     //最后过pinner
//     var CertificatePinner = Java.use('okhttp3.CertificatePinner');
//     // 直接遍历所有重载，不指定参数类型
//     CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, certs) {
//             console.log('[CertificatePinner] check called, bypassing');
//         };
//
// })

Java.perform(function () {
    // 1. TrustManager 万能替换（拦 SSLContext.init，L22 的 Pn 也走这里）
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var TrustManager = Java.registerClass({
        name: 'com.fatdog.reverse.TrustBypass',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function () {},
            checkServerTrusted: function () {},
            getAcceptedIssuers: function () { return []; }
        }
    });
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var init = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom');
    init.implementation = function (km, tm, sr) {
        init.call(this, km, [TrustManager.$new()], sr);
    };

    // 2. HostnameVerifier 放行（Pn$1 是匿名类，hook 接口方法即可，用类名也行）
    try {
        var verifier = Java.use('com.fatdog.reverse.Aw$1');
        verifier.verify.implementation = function (hostname, session) {
            console.log('[L23] HostnameVerifier bypass: ' + hostname);
            return true;
        };
    } catch (e) {
        console.log('[L23] Pn$1 not found, skip (hostname 校验本身对 127.0.0.1/localhost 就放行)');
    }

    // 3. ★ CertificatePinner：必须 hook check$okhttp（OkHttp 4.x 真正的校验点）
    var CP = Java.use('okhttp3.CertificatePinner');
    // 3a. 兜底：hook check$okhttp（真正的校验逻辑在这里）
    try {
        CP['check$okhttp'].implementation = function (hostname, fn) {
            console.log('[L22] pinner check$okhttp bypass: ' + hostname);
            // 直接 return，什么都不做 = 吞掉 pin 校验
        };
    } catch (e) {
        console.log('[L22] check$okhttp not found: ' + e);
    }
    // 3b. 再兜底：varargs 版 check(String, Certificate...)
    try {
        CP.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (hostname, certs) {
            console.log('[L22] pinner check(varargs) bypass: ' + hostname);
        };
    } catch (e) {
        console.log('[L22] check varargs not found: ' + e);
    }


    var z = Java.use('com.fatdog.reverse.Z24Core')
    z.assertGuard.implementation = function () {
        return true;
    }
});
