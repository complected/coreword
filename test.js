import { test } from 'tapzero';

import { scry, sign, ubye, pkey } from './coreword.js';

const sk = ubye("0x309a49dcda67245af724a05ff081b0c5d24ec0b87a1393d940de6c1dd60f45a3");
const pk = pkey(sk);

test('scry', async _ => {
  const verify = msg_str => test(
    String.raw`${msg_str}:`,
    async t => {
      const msg = ubye(msg_str);
      const sig = await sign(msg, sk);
      t.equal(scry(msg, pk, sig), pk);
    }
  );
  verify("What is real? That which is irreplacable.");
  verify("");
  verify("\\n");
  verify(String.raw`"\\u0024"`);
});
