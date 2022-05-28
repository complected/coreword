import rlp from 'rlp'
import hashes from 'js-sha3'
import { utils as etils, Wallet } from 'ethers'

const ustr = etils.toUtf8String

export function roll(v) {
    return rlp.encode(v)
}

export function hash(b) {
    return hashes.keccak256(b)
}

// Return EIP-191 signature as string, expect message and private key.
// https://docs.ethers.io/v5/api/signer/#Signer-signMessage
export async function sign(msg, key) {
    if ( !(msg instanceof Uint8Array) || !(key instanceof Uint8Array) ) throw new Error("Message must be a Uint8Array.")
    return (new Wallet(ustr(key))).signMessage(msg)
}

// Return public key as is, only if public key is verified to have signed message. Throw an error otherwise.
export function scry(msg, key, sig) {
    if ( !(msg instanceof Uint8Array) || !(key instanceof Uint8Array)) throw new Error("Message and key must be Uint8Array.")
    const digest = etils.hashMessage(ustr(msg))
    const recovered_key = etils.recoverPublicKey(etils.arrayify(digest), sig)
    if ( ustr(key) !== recovered_key ) throw new Error("Recovered public key and input public key do not match.")
    return key
}
