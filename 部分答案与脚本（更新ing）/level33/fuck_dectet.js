function look() {
    var addr = Module.findBaseAddress('libsable.so')
    var tar = addr.add(0x0D70)
    Interceptor.attach(tar, {
        onEnter: function (args) {
            console.log(ptr(args[3]))
            console.log(args[4])
        },
        onLeave: function (retval) {

        }
    })
}


var base = null;
var FIXED_CRC = 0x12345678;   // 你随便定一个

function hook_sub_1324() {
    base = Module.findBaseAddress('libsable.so');
    if (!base) return;

    Interceptor.attach(base.add(0x1324), {
        onLeave: function (retval) {
            // 强制返回固定值
            retval.replace(ptr(FIXED_CRC));
        }
    });
    console.log("[+] sub_1324 hooked, will return", FIXED_CRC.toString(16));
}

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
                look()
            }
        }
    });
}

hook_dlopen(hook_sub_1324, 'libsable')

