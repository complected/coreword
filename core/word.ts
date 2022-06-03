import rlp from 'rlp'
import hashes from 'js-sha3'
import * as secp from "@noble/secp256k1"

type Blob = Buffer
type Roll = Blob | Roll[]
type Hash = Blob // 32 bytes
type Pubk = Blob // 33 bytes. test.js [8]
type Seck = Blob // 32 bytes. test.js [9]
type Sign = Blob // 65 bytes. test.js [7]
type Hexs = string // hex string

export function blob(hex : Hexs) : Blob {
    return Buffer.from(hex, 'hex')
}

export function roll(r : Roll) : Blob {
    return Buffer.from(rlp.encode(r))
}

export function hash(b : Blob) : Hash {
    return Buffer.from(hashes.keccak256(b), 'hex')
}

// Return r, s, and v concatenated.
export async function sign(msg: Blob, key: Seck, opts: any = { fake: false }): Promise<Sign> {
    if (opts.fake === true) {
        return Buffer.from('fakes'.repeat(13)) // 65 bytes
    } else {
        const [sig, recovery] = await secp.sign(msg, key, { recovered: true, der: false })
        return Buffer.concat([sig, Buffer.from([recovery])])
    }
}

// Return (compressed) public key.
export function scry(msg : Blob, sig : Sign, opts : any = {fake:false}) : Pubk {
    if (opts.fake === true) {
        return Buffer.concat([Buffer.from([0x0]), Buffer.from('pubk'.repeat(8))]) // 33 bytes
    } else {
	    return Buffer.from(secp.recoverPublicKey(msg, sig.slice(0, 64), sig[64], true)) // TODO: WIP
    }
}
