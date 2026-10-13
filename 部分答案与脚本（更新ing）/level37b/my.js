function look(){
    var base = Module.findBaseAddress('libink.so')
    var funcaddress = base.add(0x3338)
    var JNIEnv = Java.vm.getEnv()
    Interceptor.attach(funcaddress,{
        onEnter:function(args){
            console.log("参数1： ",args[2].toInt32())
            console.log("参数2： ",args[3].toInt32())
            console.log("参数3： ",JNIEnv.getStringUtfChars(args[4],null).readCString())
            console.log("参数4： ",JNIEnv.getStringUtfChars(args[5],null).readCString())
        },
        onLeave:function(retval){
            console.log("retval: ",JNIEnv.getStringUtfChars(retval,null).readCString())
        },
    })
}

function hook_digest(){
    var base = Module.findBaseAddress('libink.so')
    var funcaddress = base.add(0x2FE4)
    Interceptor.attach(funcaddress,{
        onEnter:function(args){
            this.outPtr = args[4]
            var realData = args[2];
            console.log("real data:", realData.readUtf8String());
            // 把它改成 "123456"
            args[2].writeUtf8String("123456");
            args[3] = ptr(6)
            console.log('-------------')
            console.log(args[0])
            console.log(args[1])
            console.log(args[2])
            console.log(args[3])
            console.log(args[4])
            console.log(args[2].readCString())
        },
        onLeave :function(retval){
            console.log("retval:", retval);
            // 直接打印输出缓冲区的原始 16 字节
            console.log("MD5 out:", hexdump(this.outPtr));
        }
    })
    // var JNIEnv = Java.vm.getEnv()
    // var func = new NativeFunction(funcaddress,'pointer',[
    //     'pointer',       // a1: ink* this
    //     'pointer',       // a2: const unsigned int* (ink_table)
    //     'pointer',       // a3: const unsigned int* (实际指向字符串 "Fatdog_blot|iv")
    //     'pointer',
    //     'pointer',          // a5: unsigned int（输出缓冲区地址）
    //     'pointer'
    // ])
    // var data = Memory.allocUtf8String('123456')
    // var datalen = 6
    // var outbuff = Memory.alloc(16)
    // var result = func(a1,a2,data,ptr(datalen),outbuff,ptr(0))
    // console.log("主动调用 ",result)
}

// function hook_digest() {
//     var base = Module.findBaseAddress('libink.so');
//     var funcaddress = base.add(0x2FE4);
//
//     Interceptor.attach(funcaddress, {
//         onEnter: function(args) {
//             this.outPtr = args[4];
//
//             console.log('-------------');
//             console.log("this:", args[0]);
//             console.log("table:", args[1]);
//             console.log("data:", args[2]);
//             console.log("len:", args[3].toInt32());
//             console.log("out:", args[4]);
//             console.log("orig data:", args[2].readUtf8String());
//             console.log("orig len:", args[3].toInt32());
//
//             // 直接覆写 args[2] 指向的内容
//             args[2].writeUtf8String("123456");
//
//             // 同步改长度
//             args[3] = ptr(6);
//
//             console.log("new data:", args[2].readUtf8String());
//             console.log("new len:", args[3].toInt32());
//         },
//         onLeave: function(retval) {
//             console.log("retval:", retval);
//             if (this.outPtr) {
//                 console.log("MD5 out:", hexdump(this.outPtr, { length: 16 }));
//
//                 var bytes = new Uint8Array(this.outPtr.readByteArray(16));
//                 var hex = Array.from(bytes)
//                     .map(b => ('0' + b.toString(16)).slice(-2)).join('');
//                 console.log("MD5 hex:", hex);
//             }
//         }
//     });
// }
function hook_dlopen(func, bagname) {
    var dlopen = Module.findExportByName(null, "dlopen");
    Interceptor.attach(dlopen, {
        onEnter: function (args) {
            var so_name = args[0].readCString();
            if (so_name.indexOf(bagname) >= 0) {
                console.log(so_name)
                this.hook_true = true;
            }
        },
        onLeave: function (retval) {
            if (this.hook_true) {
                func()
                // hook_partb()
            }

        }
    });
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    Interceptor.attach(android_dlopen_ext, {
        onEnter: function (args) {
            var so_name = args[0].readCString();
            if (so_name.indexOf(bagname) >= 0) {
                console.log(so_name)
                this.hook_true = true;
            }
        }, onLeave: function (retval) {
            if (this.hook_true) {
                func()
            }
        }
    });
}

hook_dlopen(hook_digest,'libink')