function token(){
    var base = Module.findBaseAddress("libamber.so");
    var func = base.add(0x137C)
    Interceptor.attach(func,{
        onEnter: function(args){

        },
        onLeave: function(retval){
            var env = Java.vm.getEnv();
            console.log(env.getStringUtfChars(retval,null).readCString());//8字节随机数
        },
    })
}



function hexToBytes(hex) {
    var bytes = [];
    for (var i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

//hook篡改传入的证书，让其一直为原始证书
function change_der(){
    var hex_der = "30820313308201fba00302010202080437cb71610e1066300d06092a864886f70d01010b05003037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f69642044656275673020170d3236303930333135353734325a180f32303534303131393135353734325a3037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f696420446562756730820122300d06092a864886f70d01010105000382010f003082010a0282010100d0461f8972714155175cf4608f4058cf5460ee8858b21b8d70870380b78d1700f3613526c28c0e5e0c9fce41a28c30b323075c5af6a52222d37bc705242895c42431e5c180b21ff185168aea97a1278d86fa66e9829ba6f91753779125491d8b1a979ed133c4446f9a54832b6d5b8aa3e812b622610c212df882339ad3ee6ff4dd827b22d20ca11215064fffd48714cea829f7c158813475e84c46ea4a3a3501f6a50daaa0cc3d3e6d2bb06fc8a6fc9cc6748d85ac8ed48a8e471af4d70e31b46576963bdfd5ba3ca760eeb05fa6f0dcd226be044fb21caa6446f6a8b51907a1fe04b13cfcf4fa18d63b4f39d1a8b56a4fbe8789e2923d57898d16659a88bf850203010001a321301f301d0603551d0e0416041464e129594e36d23aa9c5c3312f0695bc9b72c280300d06092a864886f70d01010b0500038201010019f6218f6a357d778c925515e390feab4196a63bd8f91e138cfc3217b5ca6d80f0141328a79b1696d05cdd4a5a759bc61f4cc18d63b3a75377d70fba7ce563b931e7a4db68866778d35b444db83dc585812b1dc5e63711dffdff3e84b47bf3507f9f9139869a4e7a9ac4eb147d7eb84756a70f67c94072446bfe079c4a90232506d1f119e9ac91feb55a602dbd7537e7d06290f1cab2a4c40c32c3db2098d280606cd00e4efc583177f32d9d800792cb5b4ae0003acb586b6073fb7b745a9e5081cb2a3528f96f43d3aba9d944087d6c9d04b92de603597f198ee2412bef5bc2406b004d428cbaf3a8ea2dcd65f36631984e8845a4f460b91d9cb875d40fb37d"
    var base_addr = Module.findBaseAddress('libamber.so');
    var func_addr = base_addr.add(0x0BE0)
    var derBytes = hexToBytes(hex_der);
    Interceptor.attach(func_addr,{
        onEnter:function(args){
            var env = Java.vm.getEnv()
            var newarray = env.newByteArray(derBytes)
            var nativeBuf = Memory.alloc(derBytes.length);
            for (var i = 0; i < derBytes.length; i++) {
                nativeBuf.add(i).writeU8(derBytes[i]);
            }
            env.setByteArrayRegion(newarray, 0, derBytes.length, nativeBuf);

            // 3. 替换 a3
            args[2] = newarray;

            console.log("[*] replaced cert array, len=" + derBytes.length);
        },
        onLeave:function(retval){
        }
    })
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
            }
        }
    });
}
hook_dlopen(change_der,"libpearl")

