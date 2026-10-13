Java.perform(function () {
    var signutil = Java.use("com.fatdog.reverse.SignUtil");
    //创建一个实例
    var obj = signutil.$new();
    console.log("新创建的实例的指纹：", obj.cachedFingerprint)
    var acc = obj.fingerprint();
    console.log("调用方法后的指纹：", obj.cachedFingerprint);
    console.log("调用方法后的指纹结果值：", acc);//c2fb08b69f270e9aae6e76438ec724a3
})

//捕获实例，执行回调函数。
function hook() {
    Java.perform(function () {
        var ret = null;
                var rest = null;

        Java.choose("com.fatdog.reverse.SignUtil", {    //要hook的类
            onMatch: function (instance) {
                ret = instance.accountSeed(); //要hook的方法
            },
            onComplete: function () {
                console.log(ret)
                Java.choose("com.fatdog.reverse.KBox", {
                    onMatch: function (obj) {
                        rest = obj.decryptToken();
                    },
                    onComplete: function () {
                        console.log(rest);
                    }
                });
            }
        });

    })
}

hook();

Java.perform(function () {


})