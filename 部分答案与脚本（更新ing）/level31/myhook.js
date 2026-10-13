var ts = 1790663197
// var enc = 893fe64f7182f31a1e13e1c73cedd8a883e0b9cf
//sign = c6c31757c9a3b70744b1911d6b62d52662960174eb4c0ed32472f49d09dac4eb
// function hook_parta(){
//     Java.perform(function() {
//         var o1 = Java.use('o1')
//         var result = o1.partA()
//         console.log(result)//Fatdog_
//         return result
//     })
// }
// hook_parta()

function hook_enc(){
    var addr = Module.findBaseAddress('libquill.so')
    let offset = 0x0e0c
    var funcaddr = addr.add(offset)
    Interceptor.attach(funcaddr,{
        onEnter:function(args){
            console.log(args[0])
            console.log(args[1])
            console.log(args[2].toInt32())
            console.log(args[3].toInt32())
        },
        onLeave:function(retval){
            var env = Java.vm.tryGetEnv();
            var s = env.getStringUtfChars(retval, null).readCString();
            console.log("retval raw:", retval)
            console.log("retval as jstring:", s);
        }
    })
}
//密钥：Fatdog_lonely
function hook_partb(){
    var addr = Module.findBaseAddress('libquill.so')
    let offset = 0x1088
    var funcaddr = addr.add(offset)
    Interceptor.attach(funcaddr,{
        onEnter:function(args){
            console.log(hexdump(args[0]))
            this.out = args[0]
        },
        onLeave:function(retval){
            // var env = Java.vm.tryGetEnv();
            // var s = env.getStringUtfChars(retval, null).readCString();
            console.log("retval raw:", retval.toInt32())
            console.log("result :", hexdump(this.out))
            // console.log("retval as jstring:", s);
        }
    })
}

function hook_dlopen(func,bagname) {
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
                // hook_partb()
            }
        }
    });
}

hook_dlopen(hook_enc,'libquill')
