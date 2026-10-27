//可以hook两处：一个fopen，另一个直接hook这个函数 Wn.passApkPath(getApplicationInfo().sourceDir);
function bypass(){
    const fopenPtr = Module.findExportByName("libc.so", "fopen");
    Interceptor.attach(fopenPtr,{
        onEnter: function(args){
            var path = args[0].readCString();
            if (path && path =="/data/app/com.fatdog.reverse-SDTiu-EcYf4xry4e_zWVjA==/base.apk") {
                console.log("[fopen] 实际路径: " + path);//[fopen] 实际路径: /data/app/com.fatdog.reverse-SDTiu-EcYf4xry4e_zWVjA==/base.apk
                //我们只需要把这个路径重定向即可，首先得拿到没有被修改过的apk。
                var re_path=Memory.allocUtf8String("/sdcard/FatdogReverse.apk")
                console.log(re_path);
                args[0]=re_path;
            }
        },
        onLeave:function(result){},
    })
}
bypass();

Java.perform(function() {
    var m = Java.use("com.fatdog.reverse.Wn")
    console.log(m.hmacKey())
})