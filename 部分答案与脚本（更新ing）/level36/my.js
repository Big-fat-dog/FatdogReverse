function hook(){
    console.log("hook已安装")
    var baseaddr=Module.findBaseAddress('libvigor.so')
    var funcadd = baseaddr.add(0x12BC);
    Interceptor.attach(funcadd, {
        onEnter:function(args){
            console.log(args[2].toInt32());
        },
        onLeave:function(retval){
            console.log(retval)
        },
    });
}
