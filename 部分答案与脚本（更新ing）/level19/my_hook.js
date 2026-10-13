/*
[MI 8 UD::com.fatdog.reverse ]-> Hook 已加载，等待调用...

[Cipher] 算法: AES/ECB/PKCS5Padding
输入: 706167653d312674733d31373839343733383439
输出: 47f66a1e321b0680a9a3ef07a2fdff7526b4f4a3693a52b4e905881542047340
调用栈:
java.lang.Exception
        at javax.crypto.Cipher.doFinal(Native Method)
        at r0.b(SourceFile:33)
        at j.b(SourceFile:40)
        at com.fatdog.reverse.v9Activity.loadPage(SourceFile:201)
        at com.fatdog.reverse.v9Activity.onCreate(SourceFile:194)
        at android.app.Activity.performCreate(Activity.java:7893)
        at android.app.Activity.performCreate(Activity.java:7880)
        at android.app.Instrumentation.callActivityOnCreate(Instrumentation.java:1307)
        at android.app.ActivityThread.performLaunchActivity(ActivityThread.java:3283)
        at android.app.ActivityThread.handleLaunchActivity(ActivityThread.java:3457)
        at android.app.servertransaction.LaunchActivityItem.execute(LaunchActivityItem.java:83)
        at android.app.servertransaction.TransactionExecutor.executeCallbacks(TransactionExecutor.java:135)
        at android.app.servertransaction.TransactionExecutor.execute(TransactionExecutor.java:95)
        at android.app.ActivityThread$H.handleMessage(ActivityThread.java:2044)
        at android.os.Handler.dispatchMessage(Handler.java:107)
        at android.os.Looper.loop(Looper.java:224)
        at android.app.ActivityThread.main(ActivityThread.java:7562)
        at java.lang.reflect.Method.invoke(Native Method)
        at com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:539)
        at com.android.internal.os.ZygoteInit.main(ZygoteInit.java:950)


[Mac] 算法: HmacSHA256
输入: 34376636366131653332316230363830613961336566303761326664666637353236623466346133363933613532623465393035383831353432303437333430
输出: d83a7f44bedce992c79c25e30786fbbec37f7e3fdca529c335aeaaac1f13c8d2
调用栈:
java.lang.Exception
        at javax.crypto.Mac.doFinal(Native Method)
        at r0.f(SourceFile:53)
        at j.b(SourceFile:41)
        at com.fatdog.reverse.v9Activity.loadPage(SourceFile:201)
        at com.fatdog.reverse.v9Activity.onCreate(SourceFile:194)
        at android.app.Activity.performCreate(Activity.java:7893)
        at android.app.Activity.performCreate(Activity.java:7880)
        at android.app.Instrumentation.callActivityOnCreate(Instrumentation.java:1307)
        at android.app.ActivityThread.performLaunchActivity(ActivityThread.java:3283)
        at android.app.ActivityThread.handleLaunchActivity(ActivityThread.java:3457)
        at android.app.servertransaction.LaunchActivityItem.execute(LaunchActivityItem.java:83)
        at android.app.servertransaction.TransactionExecutor.executeCallbacks(TransactionExecutor.java:135)
        at android.app.servertransaction.TransactionExecutor.execute(TransactionExecutor.java:95)
        at android.app.ActivityThread$H.handleMessage(ActivityThread.java:2044)
        at android.os.Handler.dispatchMessage(Handler.java:107)
        at android.os.Looper.loop(Looper.java:224)
        at android.app.ActivityThread.main(ActivityThread.java:7562)
        at java.lang.reflect.Method.invoke(Native Method)
        at com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:539)
        at com.android.internal.os.ZygoteInit.main(ZygoteInit.java:950)


[Cipher] 算法: AES/ECB/PKCS5Padding
输入: c4108539b8aa305a7590985b24f3555cb00cd796255ac48ace7ae02f63e9da0174074dec214c481fc86a6e9059398a53
输出: 706167653d317c6e756d733d31382c39342c37322c36362c38352c38382c35332c37312c33382c3537
调用栈:
java.lang.Exception
        at javax.crypto.Cipher.doFinal(Native Method)
        at r0.a(SourceFile:43)
        at h.onResponse(SourceFile:72)
        at okhttp3.internal.connection.RealCall$AsyncCall.run(SourceFile:519)
        at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1167)
        at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:641)
        at java.lang.Thread.run(Thread.java:919)


 */

function bytesToHex(bytes) {
    var hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}

function get_aes_rsq_key() {
    Java.perform(function () {
        var p1 = Java.use("p1");
        let result = p1.a();
        console.log(bytesToHex(result));
         //66617464656d6f5f6165736b65793139

        let result2 = p1.e();
        console.log("hmac-key ",result2);
        // aes key2  102,97,116,100,101,109,111,95,104,109,97,99,95,107,101,121

        let result3 = p1.b();
        console.log("res-key ",result3);
    })
}

get_aes_rsq_key();


//瞧你妈的，defpackage的意思就是没有包名，jadx反编译出来就是这样！》？

//执行完上面的脚本我们会发现报错：Error: java.lang.ClassNotFoundException: Didn't find class "defpackage.p1" on path: DexPathList
//说明这个玩意不再默认的classloader里面，我们得去找到加载它的classloader。

//尝试寻找
// function find_classloader() {
//     Java.perform(function () {
//         var targetClassName = "defpackage.p1"; // 目标类
//         var targetLoader = null;
//
//         Java.enumerateClassLoaders({
//             onMatch: function (loader) {
//                 try {
//                     var clazz = loader.loadClass(targetClassName);
//                     targetLoader = clazz;
//                     console.log("找到了类加载器 ", clazz);
//                     console.log("classloader的类型: ", clazz.$className)
//                     // 打印这个 ClassLoader 的父级链
//                     var parent = loader.getParent();
//                     var depth = 1;
//                     while (parent != null) {
//                         console.log(" ".repeat(depth) + "└ parent: " + parent.$className);
//                         parent = parent.getParent();
//                         depth++;
//                     }
//                 } catch (error) {
//                     //没找到就继续
//                 }
//             },
//             onComplete: function () {
//                 if (targetLoader) {
//                     console.log("牛逼找到了")
//                 } else {
//                     console.log("所有类加载器均已经验证，没找到捏，操他妈的混淆");
//                 }
//             }
//         })
//     })
// }
//
// find_classloader();