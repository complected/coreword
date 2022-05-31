import { test } from 'tapzero';

import { eip191Scry, eip191Sign, ubye, pkey } from './coreword.js';

const sk = ubye("0x309a49dcda67245af724a05ff081b0c5d24ec0b87a1393d940de6c1dd60f45a3");
const pk = pkey(sk);

test('eip191Scry', async _ => {
  const verify = msg_str => test(
    String.raw`${msg_str}:`,
    async t => {
      const msg = ubye(msg_str);
      const sig = await eip191Sign(msg, sk);
      t.deepEqual(eip191Scry(msg, pk, sig), pk);
    }
  );
  verify("What is real? That which is irreplacable.");
  verify("");
  verify("\\n");
  verify(String.raw`"\\u0024"`);
});
