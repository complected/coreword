import rlp from 'rlp'
import hashes from 'js-sha3'
import * as secp from "@noble/secp256k1"

export {
    Hexs, Blob,
    Roll, Hash,
    Pubk, Seck, Sign,
    blob, roll, hash,
    sign, scry,
    Okay, fail, toss
}

type Blob = Buffer
type Roll = Blob | Roll[]
type Hash = Blob   // 32 bytes
type Pubk = Blob   // 33 bytes
type Seck = Blob   // 32 bytes
type Sign = Blob   // 65 bytes
type Hexs = string // hex string

function blob(hex : Hexs) : Blob {
    return Buffer.from(hex, 'hex')
}

function roll(r : Roll) : Blob {
    return Buffer.from(rlp.encode(r))
}

function hash(b : Blob) : Hash {
    return Buffer.from(hashes.keccak256(b), 'hex')
}

// Return r, s, and v concatenated.
async function sign(msg: Blob, key: Seck, opts: any = { fake: false }): Promise<Sign> {
    const [sig, recovery] = await secp.sign(msg, key, { recovered: true, der: false })
    return Buffer.concat([sig, Buffer.from([recovery])])
}

// Return (compressed) public key.
function scry(msg : Blob, sig : Sign, opts : any = {fake:false}) : Pubk {
    return Buffer.from(secp.recoverPublicKey(msg, sig.slice(0, 64), sig[64], true))
}


type Okay<T> = T | Error

function fail(desc:string) : Error {
    return new Error(desc)
}

function toss(desc:string) {
    throw new Error(desc)
}
