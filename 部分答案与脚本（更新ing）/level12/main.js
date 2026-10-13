// hook_l12.js
function bytesToString(b) {
        try {
            var String = Java.use('java.lang.String');
            return String.$new(b, "UTF-8");
        } catch (e) {
            return "[非UTF-8文本]";
        }
    }
Java.perform(function () {
    function b2h(b) { var s=''; for (var i=0;i<b.length;i++){var x=b[i]&0xff; s+=('0'+x.toString(16)).slice(-2);} return s; }
    var C = Java.use('javax.crypto.Cipher');
    C.doFinal.overload('[B').implementation = function (input) {
        var r = this.doFinal(input);
        console.log('[cipher] 输入:', b2h(input), '-> 输出:', b2h(r));
        console.log('[Cipher] 输入:', bytesToString(input));
        console.log('[Cipher] 输出:', bytesToString(r));
        return r;
    };
});