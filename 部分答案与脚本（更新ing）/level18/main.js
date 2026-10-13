// hook rsa

function get_rsa_public_key(){
    Java.perform(function() {
        var pk = Java.use("com.fatdog.reverse.Pk");
        let result1 = pk.modulus()
        console.log("modulus: ", result1);
        let result2 = pk.exp()
        console.log("exp: ", result2);
        let result3 = pk.desHalfB()
        console.log("desHalfB: ", result3);
    })
}

get_rsa_public_key();