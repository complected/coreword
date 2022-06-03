// @ts-check
import { utils as etils } from "ethers"
import { test } from 'tapzero'
import { sign, scry, hash } from '../dist/word.js'
import * as secp from "@noble/secp256k1"

const sk = secp.utils.randomPrivateKey()
const pk = secp.getPublicKey(sk, true)
const signKey = new etils.SigningKey(sk)

// Alternative:
// const signKey = new etils.SigningKey("0x309a49dcda67245af724a05ff081b0c5d24ec0b87a1393d940de6c1dd60f45a3")
// const [pk, sk] = [signKey.compressedPublicKey, signKey.privateKey].map(k => etils.arrayify(k))

const testcases = [
    "1",
    "What is real? That which is irreplacable.",
    "\\n",
    String.raw`"\\u0024"`,
    "!@#$",
    // Note that `length` is defined as number of UTF-16 codepoints.
    // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/length
    "α", 
    String.raw`⛓️👷‍♂️🏙️👨‍👨‍👧‍👧`,
    // About 10x lower than current V8 max string length, 2 ^ 29.
    // This is to stress test the code. You can crash the test before 2 ^ 29, but that's due to running out of heap space because of copying the string multiple times through function calls IMO.
    // https://stackoverflow.com/questions/44533966/v8-node-js-increase-max-allowed-string-length#:~:text=In%20summer%202017%2C%20V8%20increased,25%20on%2064%2Dbit%20platforms.
    "1".repeat(2 ** 26) 
]

test("Sign message and recover public key", async _ => {
    testcases.forEach(str => test(
        String.raw`${str.length < 2** 10 ? str : "VERY LONG STRING"}:`,
        async t => {
            const digest = hash(Buffer.from(str))
            const rsv = await sign(digest, sk)           // r + s + v
            const recoverdPk = scry(digest, rsv)
            t.deepEqual(recoverdPk, Buffer.from(pk))
        }
    ))
})

test("Differentially test against Ethers.js", _ => {
    testcases.forEach(str => test(
        String.raw`${str.length < 2** 10 ? str : "VERY LONG STRING"}:`,
        async t => {
            // noble
            const nprefix = "\x19Ethereum Signed Message:\n"
            const nEIP191Encode = s => new Uint8Array([
                ...Buffer.from(nprefix),
                ...Buffer.from(String(Buffer.from(s).length)), // JS strings' length are UTF16 based
                ...Buffer.from(s)
            ])
            const ndigest = hash(nEIP191Encode(str))

            // ethers
            const edigest = Buffer.from(etils.arrayify(etils.hashMessage(str)))

            // T: digest
            t.deepEqual(ndigest, edigest)

            // noble
            const nrsv = await sign(ndigest, sk)
            // Know that the recovery bit varies in test, because public+private key generation in test is non-deterministic.
            const [nrs, nrecovery] = [nrsv.slice(0, 64), nrsv[64]]

            // ethers
            // Again, ersv = r + s + v 
            const ersv = etils.arrayify(etils.joinSignature(signKey.signDigest(edigest)))
            const ers = Buffer.from(ersv.slice(0, 64))
            // Normalize the v bit: "the yParity parameter is always either 0 or 1 (canonically the values used have historically been 27 and 28..."
            // https://eips.ethereum.org/EIPS/eip-2098
            let erecovery
            if (ersv[64] === 27) {
                erecovery = 0
            } else if (ersv[64] === 28) {
                erecovery = 1
            } else {
                throw new Error("Incorrect v in test setup.")
            }

            // T: signature
            t.deepEqual(nrs, ers)
            t.deepEqual(nrecovery, erecovery)


            // noble
            const npk = scry(ndigest, nrsv)

            // ethers
            /*
            Ethers branches on the length of the signature. If it was 64 byte, it assumes EIP2098 Compact Representation,
            we want to use canonical signature. Therefore I pass in `ersv` to `recoverPublicKey` instead of `esig`. Don't pass in 64 byte.
            1. https://github.com/ethers-io/ethers.js/blob/fc1e006575d59792fa97b4efb9ea2f8cca1944cf/packages/bytes/lib/index.js#L302 
            2. "...while canonical signatures involve 3 separate parameters (r, s, yParity) and are 65 bytes long."
            https://eips.ethereum.org/EIPS/eip-2098
            */
            const epkHexStr = etils.recoverPublicKey(etils.arrayify(edigest), ersv)
            const epkHexBuf = Buffer.from(epkHexStr.slice(2), 'hex') // remove `0x`

            // T: public key
            // 1. The noble-recovered public key is compressed. Therefore, the prefix is 0x02 or 0x03 by convention in ECDSA.
            //    https://github.com/paulmillr/noble-secp256k1/blob/main/index.ts#L462
            //    https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
            //    https://docs.ethers.io/v5/api/utils/signing-key/#SigningKey
            // 2. The ethers-recoverd public key is uncompressed (I haven't found an Ethers API that compresses it). Thus, the prefix is 0x04.
            // 3. Because (1) and (2), we disregard the prefix when comparing.
            const npkNoPrefix = npk.slice(1)
            const epkCompressedNoPrefix = epkHexBuf.slice(1, 33)
            t.deepEqual(npkNoPrefix, epkCompressedNoPrefix)
        }
    ))
})

test('bad signature', t => {
    const msg = Buffer.from("1")
    const badSig = new Uint8Array(Array(64).fill(0))
    t.throws(_ => scry(msg, badSig), /Invalid Signature/)
})

// Expect Syntax error. Can't test at test time without weird hacks, hence commenting it out.
// sign(Buffer.from(""), sk) // should throw when creating BigInt (a lib that backs Noble) out of 0x (deduced from "")

/*
# References: to document links and gotchas

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
8. See (6) and (T: public key) in the test.
9. Private key returned by Noble and tested is 32 bytes: https://github.com/paulmillr/noble-secp256k1#utilities
*/
