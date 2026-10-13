Java.perform(function () {
    var candidates = ["p1", "defpackage.p1"];

    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            candidates.forEach(function (n) {
                try {
                    var c = loader.loadClass(n);
                    if (c) {
                        console.log("[+] " + n + " loaded by " + loader);
                        console.log("    class = " + c);
                        // 关键：把默认 loader 切过去，之后就能 Java.use
                        Java.classFactory.loader = loader;
                        var p1 = Java.use(n);
                        console.log("    Java.use OK: " + p1);
                    }
                } catch (e) {}
            });
        },
        onComplete: function () { console.log("=== loaders done ==="); }
    });
});