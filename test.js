import * as utf8 from '@stablelib/utf8';
import { utils as etils } from "ethers";
import { test } from 'tapzero';
import { sign, scry } from './coreword.js';
import * as sha3 from "@noble/hashes/sha3";
import * as secp from "@noble/secp256k1";

const sk = secp.utils.randomPrivateKey();
const pk = secp.getPublicKey(sk, true);
const signKey = new etils.SigningKey(sk);

// Alternative:
// const signKey = new etils.SigningKey("0x309a49dcda67245af724a05ff081b0c5d24ec0b87a1393d940de6c1dd60f45a3");
// const [pk, sk] = [signKey.compressedPublicKey, signKey.privateKey].map(k => etils.arrayify(k));

const testcases = [
  "1",
  "What is real? That which is irreplacable.",
  "\\n",
  String.raw`"\\u0024"`
];

test("Sign message and recover public key", async _ => {
  testcases.forEach(str => test(
    String.raw`${str}:`,
    async t => {
      const msg = utf8.encode(str);
      const rsv = await sign(msg, sk); // r + s + v
      const [sig, recovery] = [rsv.slice(0, -1), rsv[64]];
      t.deepEqual(scry(msg, sig, recovery), pk);
    }
  ));
});

test("Differentially test against Ethers.js", _ => {
  testcases.forEach(str => test(
    String.raw`${str}:`,
    async t => {
      // ethers
      const edigest = etils.arrayify(etils.hashMessage(str));

      // noble
      const nprefix = "\x19Ethereum Signed Message:\n";
      const nmsg = new Uint8Array([
        ...utf8.encode(nprefix),
        ...utf8.encode(String(str.length)),
        ...utf8.encode(str)
      ]);
      const ndigest = sha3.keccak_256(nmsg);

      // T: digest
      t.deepEqual(ndigest, edigest);

      // T: signature
      // Know that ECDSA signing is non-deterministic, the recovery bit varies.

      // ethers
      const ersv = etils.arrayify(etils.joinSignature(signKey.signDigest(edigest)));
      // Again, ersv = r + s + v 
      const esig = ersv.slice(0, 64);
      let erecovery;
      // Normalize: "the yParity parameter is always either 0 or 1 (canonically the values used have historically been 27 and 28..."
      // https://eips.ethereum.org/EIPS/eip-2098
      if (ersv[64] === 27) {
        erecovery = 0;
      } else if (ersv[64] === 28) {
        erecovery = 1;
      } else {
        throw new Error("Incorrect v in test setup.")
      }

      // noble
      const nrsv = await sign(ndigest, sk);
      const [nsig, nrecovery] = [nrsv.slice(0, 64), nrsv[64]];

      t.deepEqual(nsig, esig);
      t.deepEqual(nrecovery, erecovery);

      //  T: public key

      // noble
      const npk = scry(ndigest, nsig, nrecovery);

      // ethers
      /*
      Ethers branches on the length of the signature. If it was 64 byte, it assumes EIP2098 Compact Representation,
      we want to use canonical siganture.
      https://github.com/ethers-io/ethers.js/blob/fc1e006575d59792fa97b4efb9ea2f8cca1944cf/packages/bytes/lib/index.js#L302 

      Therefore I pass in ersv to recoverPublicKey instead of esig:
      "The Compact Representation does not collide with canonical signature as it uses 2 parameters (r, yParityAndS)
      and is 64 bytes long while canonical signatures involve 3 separate parameters (r, s, yParity) and are 65 bytes long."
      https://eips.ethereum.org/EIPS/eip-2098
      */
      const epkUncompressed = etils.arrayify(etils.recoverPublicKey(etils.arrayify(edigest), ersv));
      // compressed pk's prefix is ether 0x02 or 0x03 and non-deterministic, so we don't compare it. https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
      // compressed key is the slice(1, 33) of uncompressed.
      t.deepEqual(npk.slice(1), epkUncompressed.slice(1, 33));
    }
  ))
});

test('bad signature', t => {
  const msg = utf8.encode("1");
  const badSig = new Uint8Array(Array(64).fill(0))
  t.throws(_ => scry(msg, badSig, pk), /Invalid Signature/);
});

// sign(utf8.encode(""), sk) // should throw when creating BigInt (a lib that backs Noble) out of 0x

// Primer on ECDSA: https://blog.cloudflare.com/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/