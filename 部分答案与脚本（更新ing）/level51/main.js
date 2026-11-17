function m6(){
    var addr=Module.findBaseAddress("libshark.so")
    var func=addr.add(0x5DB4)
    Interceptor.attach(func,{
        onEnter:function(args){
            console.log("安装成功")
            console.log(args[3].toInt32())
        },
        onLeave:function(retval){},
    })
}
m6()