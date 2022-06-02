import * as secp from "@noble/secp256k1";

// Return r, s, and v concatenated. [7]
export const sign = async function sign(msg, sk) {
	const [sig, recovery] = await secp.sign(msg, sk, { recovered: true, der: false });
	return new Uint8Array([...sig, ...[recovery]]);
};

// Return prefixed public key (33 byte): 1 (prefix, either 0x02 or 0x03) + 32 (key size). [6]
export const scry = function scry(msg, sig) {
	return secp.recoverPublicKey(msg, sig, recovery, true);
};

/*
References:

1. https://github.com/paulmillr/noble-secp256k1
2. https://blog.cloudflare.com/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/
3. comments in test.js
4. rabbit hole: https://ethereum.github.io/yellowpaper/paper.pdf
5. https://github.com/ethereumbook/ethereumbook/blob/develop/06transactions.asciidoc#transaction-signing-in-practice
6. In Bitcoin, public keys are either compressed or uncompressed. Compressed public keys are 33 bytes,
consisting of a prefix either 0x02 or 0x03, and a 256-bit integer called x. The older uncompressed keys are 65 bytes,
consisting of constant prefix (0x04), followed by two 256-bit integers called x and y (2 * 32 bytes).
The prefix of a compressed key allows for the y value to be derived from the x value.
https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
7. Same as Ethers' Raw Signature, 65 bytes = 32 (r) + 32 (s) + 1 (v). https://docs.ethers.io/v5/api/utils/bytes/#Signature

*/