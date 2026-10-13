/*
方案一：直接静态分析复原
A = [85, 65, 90, 87];
B = [59]
function dec(Arr,i){
    var bytes = []
    for(let j=0;j<Arr.length;j++){
        bytes[j] = Arr[j] ^ i;
    }
    let result = ""
    for(j=0;j<Arr.length;j++){
        result+=String.fromCharCode(bytes[j]);
    }
    return result;
}
function seed(){
    return dec(A, 51) + dec(B, 90);
}
console.log(seed())
*/

//方案2：frida动态hook哈希算法
function bytesToHex(bytes){
    var str=''
    for(let i=0;i<bytes.length;i++){
        str+=('0'+bytes[i]&0xFF).toString(16).slice(-2);
    }
    return str;
}
Java.perform(function(){
    var MD = Java.use("java.security.MessageDigest")
    MD.update.overload('[B').implementation = function(d){
        console.log("Digest输入hex:",bytesToHex(d))
        return this.update(d)
    };
    MD.digest.overload('[B').implementation = function (d) {
        console.log('[digest] 输入 hex:', bytesToHex(d));
        return this.digest(d);
    };
    console.log('[seed] 还原结果 =', Java.use('com.fatdog.reverse.HashSeed').seed());
})