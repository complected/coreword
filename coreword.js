import * as secp from "@noble/secp256k1";
import * as utf8 from "@stablelib/utf8";

// https://github.com/paulmillr/noble-secp256k1

const sign = async function sign(msg, sk) {
	return secp.sign(msg, sk, { recovered: true, der: false });
}

const scry = function scry(msg, sig, recovery) {
	return secp.recoverPublicKey(msg, sig, recovery, true);
}

// REPL

const sk = secp.utils.randomPrivateKey();
const pk = secp.getPublicKey(sk, true);
const msg = utf8.encode("hello world");
const [sig, recovery] = await sign(msg, sk);

console.log(secp.verify(sig, msg, pk)) // true
console.log(scry(msg, sig, recovery), pk)
/*
Uint8Array(33) [
    3, 169,   4, 206,  31, 114,  71, 182,
   56,  56,  19,  91,  34, 139, 153, 187,
  115, 102, 207, 198, 224, 239, 182, 108,
  113, 145, 151,  20, 246, 167, 109,  48,
   17
] Uint8Array(33) [
    3, 169,   4, 206,  31, 114,  71, 182,
   56,  56,  19,  91,  34, 139, 153, 187,
  115, 102, 207, 198, 224, 239, 182, 108,
  113, 145, 151,  20, 246, 167, 109,  48,
   17
]
*/