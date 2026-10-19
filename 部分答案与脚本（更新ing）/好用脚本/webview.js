function stackTrace() {
    return Java.use('android.util.log').getStackTraceString(
        Java.use("java.lang.Exception").$new()
    )
}

function find_Web() {
    Java.perform(function () {
        var webview = Java.use("android.webkit.WebView");

        webview.$init.overloads.forEach(function (overload) {
            overload.implementations = function () {
                console.log('[*] hook webview constructor');
                console.log("    overload: " +
                    overload.argumentTypes.map(t => t.className).join(", "));
                stackTrace();
                return overload.apply(this, arguments);
            }
        })

        webview.loadUrl.overloads.forEach(function (overload) {
            overload.implementation = function () {
                console.log("\n[+] WebView.loadUrl()");
                console.log("    URL: " + arguments[0]);
                stackTrace()
                return overload.apply(this, arguments);
            };
        });

        // 3. 观察 JavaScript 接口注册
        webview.addJavascriptInterface.overloads.forEach(function (overload) {
            overload.implementation = function (obj, name) {
                console.log("\n[+] addJavascriptInterface()");
                console.log("    name: " + name);
                console.log("    object class: " + obj.$className);
                stackTrace()
                return overload.call(this, obj, name);
            };
        });

        console.log("[+] WebView hooks installed");
    })
}
find_Web();