function look(){
    var base = Module.findBaseAddress('libbadger.so')
    var funcaddress=base.add(0x36A4)
    Interceptor.attach(funcaddress, {
        onEnter:function(args){
            console.log(args[2].toInt32());
            console.log(args[3].toInt32());
        },
        onLeave:function(retval){
            var JNIEnv = Java.vm.getEnv();
            console.log("result: ",JNIEnv.getStringUtfChars(retval,null).readCString());
        },
    });

}
// look()

function get_part_key(){
    Java.perform(function() {
        var e1 = Java.use('e1')
        e1.half.implementation = function(i){
            console.log(i)
            var result = this.half(i)
            console.log(result)
            return result
        }
    })
}
get_part_key();