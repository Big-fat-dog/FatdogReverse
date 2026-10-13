const CryptoJS = require('crypto-js');

const content = "GRANTED_2026_OK!";
const key1 = "PIVOT_KEY_B_0001";
const key2 = "PIVOT_KEY_A_0001";

const key1Bytes = CryptoJS.enc.Utf8.parse(key1);
const key2Bytes = CryptoJS.enc.Utf8.parse(key2);

// 明文先异或 90
function xor(str) {
    const bytes = Buffer.from(str, 'utf8');
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = bytes[i] ^ 90;
    }
    return CryptoJS.lib.WordArray.create(bytes);
}

const xored = xor(content);

// 第一次 AES-ECB，无填充
const encB = CryptoJS.AES.encrypt(xored, key1Bytes, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.NoPadding
}).ciphertext;

// 第二次 AES-ECB，无填充
const encA = CryptoJS.AES.encrypt(encB, key2Bytes, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.NoPadding
}).ciphertext;

// 输出 base64
const license = CryptoJS.enc.Base64.stringify(encA);
console.log(license);   // /ypiwyDoIxHtJkdhGceyRw==