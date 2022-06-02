import * as secp from "@noble/secp256k1";

// https://github.com/paulmillr/noble-secp256k1

// Return r + s + v concatenated, same as Ethers' Raw Signature, 65 bytes = 32 (r) + 32 (s) + 1 (v). 
// https://docs.ethers.io/v5/api/utils/bytes/#Signature
export const sign = async function sign(msg, sk) {
	const [sig, recovery] = await secp.sign(msg, sk, { recovered: true, der: false });
	return new Uint8Array([...sig, ...[recovery]]);
};

// Return prefixed public key (33 byte), 1 (prefix, either 0x02 or 0x03) + 32 (key size).
// https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
export const scry = function scry(msg, sig, recovery) {
	return secp.recoverPublicKey(msg, sig, recovery, true);
};
