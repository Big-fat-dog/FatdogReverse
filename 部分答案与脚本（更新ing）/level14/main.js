//我们可以看到解密后的字符串，但他验证的输入是加密，所以我们要事先对其进行加密
//"GRANTED_2026_OK!"->AES ECB ->AES ECB。两次ECB加密，并且密钥不同哦
const CryptoJS = require("crypto-js");

var content = "GRANTED_2026_OK!"
key1 = "PIVOT_KEY_B_0001"
const key2 = "PIVOT_KEY_A_0001"
//第一次加密之前，他对原文进行了异或90
var key1Bytes = CryptoJS.enc.Utf8.parse(key1);
var key2Bytes = CryptoJS.enc.Utf8.parse(key2);

function xor(str){
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);

    for(let i=0;i<bytes.length;i++){
        bytes[i] = bytes[i]^90;
    }
    return CryptoJS.lib.WordArray.create(bytes);
}
const enc_data = CryptoJS.AES.encrypt(xor(content),key1Bytes,{
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.NoPadding
}).ciphertext;
const eenc_data = CryptoJS.AES.encrypt(enc_data,key2Bytes,{
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.NoPadding
})
console.log(CryptoJS.enc.Base64.stringify(eenc_data))

const mm = CryptoJS.MD5("pivot_device").toString();
console.log(mm);

// Java.perform(function(){
//     var piv = Java.use("com.fatdog.reverse.PivotParts")
//     var obj = piv.$new();
//     const result = obj.deviceId()
//     console.log(result);//pivot_device
// });