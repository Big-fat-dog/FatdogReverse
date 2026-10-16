function get_ca() {
    Java.perform(function () {
        var tm = Java.use("com.fatdog.reverse.Tm")
        tm.caDer.implementation = function () {
            var result = this.caDer()
            console.log(result)
            return result
        }
    })
}

// get_ca();

Java.perform(function () {
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");

    var MyTrustManager = Java.registerClass({
        name: 'com.fatdog.reverse.TrustBypass',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function () {
            },
            checkServerTrusted: function () {
            },
            getAcceptedIssuers: function () {
                return [];
            }
        }
    })


    var tm = MyTrustManager.$new();

    SSLContext.init.implementation = function (km, oldTm, random) {

        console.log("[+] SSLContext.init() intercepted");

        var newTm = Java.array(
            "javax.net.ssl.TrustManager",
            [tm]
        );

        console.log("[+] Replacing TrustManager");

        return this.init(km, newTm, random);
    };

    console.log("[+] Hook installed");
});