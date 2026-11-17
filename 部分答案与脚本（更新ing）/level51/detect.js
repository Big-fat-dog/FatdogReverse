function to_str(array,num){
    output=[]
    for(i=0;i<array.length;i++){
        output[i]=array[i]^num
    }
    console.log(new TextDecoder().decode(new Uint8Array(output)))
}
arr1=[0xD, 0x2A, 0x3F, 0x2F, 0x24, 0x2C, 0x14, 0x3F, 0x23,0x3E, 0x25, 0x2F, 0x2E, 0x39, 0x14, 0x79, 0x7B, 0x79,0x7D, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B]
to_str(arr1,0x4B)
console.log("page=1&ts=1794663996".length)
//.rodata:0000000000001032                 DCB 0x7D, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B  注意这里几个零没显示出来，真特么阴啊！所以密钥要再补5个0
// .rodata:0000000000001038



function d(){
    var offset = 14940
    var arr= [15106, 15003, 15194, 15236, 15216];
    var output = []
    for(let i=0; i<arr.length; i++){
        output[i]=((((arr[i] - offset) - (i * 19)& 65535))^ ((1911141589>> (i * 4)) & 255));
    }
    return new TextDecoder().decode(new Uint8Array(output))
}
console.log(d())
