import { test } from 'tapzero'

import { roll, scry, sign } from './coreword.js'

import { utils as etils } from 'ethers'

const ubyte = etils.toUtf8Bytes
const sk_txt = "0x309a49dcda67245af724a05ff081b0c5d24ec0b87a1393d940de6c1dd60f45a3"
const sk = ubyte(sk_txt)
const pk_txt = etils.computePublicKey(sk_txt)
const pk = ubyte(pk_txt)

test('roll', t=>{
    t.ok(roll([]))
})

test('scry', async _=>{
    const verify = msg=> test(
        String.raw`TEST: ${msg}`,
        async t=> t.equal(
            scry(
                ubyte(msg),
                pk,
                await sign(ubyte(msg), sk)
            ),
            pk
        )
    )
    verify("What is real? That which is irreplacable.")
    verify("")
    verify("\\n")
    verify(String.raw`"\\u0024"`)
})
