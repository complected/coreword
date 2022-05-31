import { utils as etils, Wallet } from 'ethers';

const ustr = etils.toUtf8String;
const ubye = etils.toUtf8Bytes;
const ucat = etils.concat;
const aray = etils.arrayify;

// For simplicity, all functions below should take and return Uint8Array.
const verifyIns = function verifyIns(...args) {
	args.forEach(x => {
		if (!(x instanceof Uint8Array)) throw new Error(`Arguments must be Uint8Array:\n ${x}`);
	});
};

const pkey = function pkey(skey) {
	verifyIns(skey);
	return ubye(etils.computePublicKey(ustr(skey)));
};

 // Return the EIP-191 personal message digest of message.
 // https://docs.ethers.io/v5/api/utils/hashing/#utils-hashMessage
const eip191Digest = function eip191Digest(msg) {
	verifyIns(msg);
	return ubye( etils.hashMessage(ustr(msg)) );
};

// Return EIP-191 signature.
// https://docs.ethers.io/v5/api/signer/#Signer-signMessage
const eip191Sign = async function eip191Sign(msg, key) {
	verifyIns(msg, key);
	return ubye( await (new Wallet(ustr(key))).signMessage(msg) );
};

// Return public key as is, only if public key is verified to have (EIP191) signed message. Throw an error otherwise.
const eip191Scry = function eip191Scry(msg, key, sig) {
	verifyIns(msg, key, sig);
	const digest = ustr(eip191Digest(msg));
	const recovered_key = etils.recoverPublicKey(aray(digest), ustr(sig));
	if (ustr(key) !== recovered_key) throw new Error("Recovered public key and input public key do not match.");
	return key;
};

export {
	ustr,
	ubye,
	ucat,
	aray,
	pkey,
	eip191Digest,
	eip191Sign,
	eip191Scry
};
