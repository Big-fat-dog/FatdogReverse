//hook加密算法拿不到结果，那我们尝试来hook一下string相关的生成
global.is_ok = false;

function stackTrace() {
    //用于打印函数调用栈
    var log = Java.use("android.util.Log");
    return log.getStackTraceString(Java.use("java.lang.Exception").$new());
}

//非常之危险，容易炸内存
function hook_stringBuilder() {

    Java.perform(function () {
            console.log("StringBuilder Hook 已加载");

            var sb = Java.use("java.lang.StringBuilder");
            sb.append.overload("java.lang.String").implementation = function (s) {
                if (global.is_ok) {
                    console.log("[StringBuilder.append] " + s);
                    console.log("调用栈:\n", stackTrace());
                }
                return this.append.call(this, s);
            }

            // Hook append(int)
            sb.append.overload("int").implementation = function (i) {
                if (global.is_ok) {
                    console.log("[StringBuilder.append] " + i);
                }
                return this.append.call(this, i);

            };

            // Hook append(Object)
            sb.append.overload("java.lang.Object").implementation = function (o) {
                if (global.is_ok) {
                    console.log("[StringBuilder.append] " + o);
                }
                return this.append.call(this, o);

            };

            // Hook toString —— 看最终拼出来的字符串
            sb.toString.implementation = function () {
                var result = this.toString();

                if (global.is_ok) {
                    console.log("\n[StringBuilder.toString] " + result);
                    console.log("  调用栈:\n" + stackTrace());
                }
                return result;

            };


        }
    )

}

//非常之危险+1，容易炸内存
function hook_arraylist() {
    var ArrayList = Java.use("java.util.ArrayList");

    // Hook add(Object)
    var addHandle = ArrayList.add.overload("java.lang.Object");
    ArrayList.add.overload("java.lang.Object").implementation = function (o) {
        if (global.is_ok) {
            var str = o ? o.toString() : "null";
            console.log("[ArrayList.add] " + str);
        }
        return addHandle.call(this, o);   // 用句柄，不是 this.add
    };

    // Hook toString —— 看整个列表最终内容
    // var toStringHandle = ArrayList.toString.overload();
    // toStringHandle.implementation = function () {
    //     var result = toStringHandle.call(this);
    //     if (global.is_ok && result !== null) {
    //         var str = result.toString();
    //         console.log("\n[ArrayList.toString] " + str);
    //     }
    //     return result;
    // };

    console.log("ArrayList Hook 已加载");
}

function get_Key() {
    Java.perform(function () {
        try {
            var fl = Java.use("com.fatdog.reverse.Fl");
            let result = fl.buildReqKey();
            console.log("buildReqKey: ", result);

            let result2 = fl.buildSigSalt();
            console.log("buildSigSalt: ", result2);

            let result3 = fl.buildRspKey();
            console.log("buildRspKey: ", result3);
        } catch (e) {
            console.log(e, "hook失败");
        }
    })


}

// function hook_Fl() {
//     Java.perform(function () {
//         var targetClass = "com.fatdog.reverse.Fl";
//
//         // 先尝试直接 use，如果类已加载就直接 hook
//         try {
//             var fl = Java.use(targetClass);
//             doHook(fl);
//             console.log("[+] Fl 已直接 hook");
//             return;
//         } catch (e) {
//             console.log("[*] Fl 尚未加载，等待类加载...");
//         }
//
//         // 类还没加载，用 ClassLoader.loadClass 监听
//         var ClassLoader = Java.use("java.lang.ClassLoader");
//         var loadClassHandle = ClassLoader.loadClass.overload("java.lang.String");
//         loadClassHandle.implementation = function (name) {
//             var result = loadClassHandle.call(this, name);
//             if (name === targetClass) {
//                 console.log("[+] Fl 加载了，开始 hook");
//                 doHook(Java.use(targetClass));
//             }
//             return result;
//         };
//     });
// }
//
// function doHook(fl) {
//     // 静态方法用类句柄，不用 this
//     var reqKeyHandle = fl.buildReqKey.overload();
//     reqKeyHandle.implementation = function () {
//         var result = reqKeyHandle.call(this);
//         console.log("[buildReqKey] " + result);
//         return result;
//     };
//
//     var sigSaltHandle = fl.buildSigSalt.overload();
//     sigSaltHandle.implementation = function () {
//         var result = sigSaltHandle.call(this);
//         console.log("[buildSigSalt] " + result);
//         return result;
//     };
//
//     // 顺手把三个 key 都 hook 了，方便一次拿全
//     var rspKeyHandle = fl.buildRspKey.overload();
//     rspKeyHandle.implementation = function () {
//         var result = rspKeyHandle.call(this);
//         console.log("[buildRspKey] " + result);
//         return result;
//     };
//
//     var dogHandle = fl.dog.overload();
//     dogHandle.implementation = function () {
//         var result = dogHandle.call(this);
//         console.log("[dog] " + result);
//         return result;
//     };
//
//     console.log("[+] Fl hook 安装完成");
// }


function main() {
    // hook_stringBuilder();
    // hook_arraylist();
    get_Key()//拿到sm4的请求密钥
}


main()