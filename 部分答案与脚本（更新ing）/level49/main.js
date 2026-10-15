function look(){
    var base = Module.findBaseAddress('libotter.so')
    var funcaddr = base.add(0x4E30)
    Interceptor.attach(funcaddr,{
        onEnter: function(args){
            args[3]=ptr(1791888867371)
        },
        onLeave: function(retval){
            var env = Java.vm.getEnv()
            console.log(env.getStringUtfChars(retval,null).readCString());
        },
    });
}

// function get_Key(){
//     Java.perform(function() {
//         var r7 = Java.use('r7')
//         r7.mistTail.implementation=function(i){
//             console.log('mistTail')
//             console.log(i)
//             var result = this.mistTail(i)
//             console.log("mistTail调用结果: ",result)
//             return result
//         }
//         r7.forestHead.implementation=function(i){
//             console.log('forestHead')
//             console.log(i)
//             var result = this.forestHead(i)
//             console.log("forestHead调用结果: ",result)
//             return result
//         }
//     })
// }
// get_Key();