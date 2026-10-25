function get_key(){
    Java.perform(function(){
        var w = Java.use('com.fatdog.reverse.Wi')
        var result = w.hmacKey()
        console.log(result)
    })
}
get_key();//Fatdog_scan