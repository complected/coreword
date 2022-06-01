import nacl from 'tweetnacl';

// Returns signature.
export const sign = function sign(msg, key) {
	return nacl.sign.detached(msg, key);
};

// Returns public key as is, if valid, throws otherwise.
export const scry = function scry(msg, sig, key) {
	if ( !(nacl.sign.detached.verify(msg, sig, key)) ) throw new Error("Invalid signature.");
	return key;
};
