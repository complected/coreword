import { test } from 'tapzero';
import nacl from 'tweetnacl';
import utf8 from '@stablelib/utf8';
import { sign, scry } from './coreword.js';

const { publicKey: pk, secretKey: sk } = nacl.sign.keyPair();

test('scry', _ => {
  const verify = str => test(
    String.raw`${str}:`,
    t => {
      const msg = utf8.encode(str);
      const sig = sign(msg, sk);
      t.deepEqual(scry(msg, sig, pk), pk);
    }
  );
  [
    "1",
    "What is real? That which is irreplacable.",
    "",
    "\\n",
    String.raw`"\\u0024"`
  ].forEach(s => verify(s));
});

test('bad signature', t => {
  const msg = utf8.encode("1");
  const badSig = new Uint8Array(Array(64).fill(0))
  t.throws(_ => scry(msg, badSig, pk), /Invalid signature/);
});
