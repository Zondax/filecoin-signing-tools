const { encode, decode } = require('@ipld/dag-cbor')
const { CID } = require('multiformats')
const raw = require('multiformats/codecs/raw')
const { identity } = require('multiformats/hashes/identity')

/* Multisig creation update */
/*
    Use this to update multisig.json
*/

const cbor_multisig_hex = "8a0042000155011eaf1c8a4bbfeeb0870b1745b1f57503470b711601430003e81a000f4240430009c4430009c402584a82d82a53000155000e66696c2f352f6d756c74697369675831848255011eaf1c8a4bbfeeb0870b1745b1f57503470b71165501dfe49184d46adc8f89d44638beb45f78fcad2590010000"

const cbor_multisig = Buffer.from(cbor_multisig_hex, "hex")
const encoded_params = decode(cbor_multisig)[9]
const cid = decode(encoded_params)[0]

// Change version when needed
identity.digest(Buffer.from('fil/6/multisig', 'utf-8'))
    .then(function (hash) {
        const newCID = CID.create(1, raw.code, hash)
        
        // I need to update encoded params too
        const encoded_params_hex = Buffer.from(encoded_params).toString('hex')
        encoded_params_hex.replace(Buffer.from(cid.bytes).toString('hex'), Buffer.from(newCID.bytes).toString('hex'))
        
        console.log('New base64 params for multisig: ' + Buffer.from(encoded_params_hex, 'hex').toString('base64'))
        console.log('New cbor value for multisig: ' + cbor_multisig_hex.replace(Buffer.from(cid.bytes).toString('hex'), Buffer.from(newCID.bytes).toString('hex')))
    })


/* Paymentchannel creation update */
/*
    Use this to update payment_channel.json
*/


const payment_channel_params_b64 = "gtgqWBkAAVUAFGZpbC81L3BheW1lbnRjaGFubmVsWEqCWDEDkwecz0UMcgWwqOxkoW5i9Z9hJ1kJsU6RpoTUrMbzIbTsQfRUMxPCBa5gAZ/snDBOVQElRUfDOAbbTJ6ACbjr2cTS5fIBgg=="

const payment_channel_params = Buffer.from(payment_channel_params_b64, "base64")
const encoded_params_payment_channel = decode(payment_channel_params)[0]

// Change version when needed
identity.digest(Buffer.from('fil/5/paymentchannel', 'utf-8'))
    .then(function (hash) {
        const newCID = CID.create(1, raw.code, hash)

        const encoded_params_hex = Buffer.from(payment_channel_params).toString('hex')
        encoded_params_hex.replace(Buffer.from(encoded_params_payment_channel.bytes).toString('hex'), Buffer.from(newCID.bytes).toString('hex'))
        
        console.log('New base64 params for payment channel: ' + Buffer.from(encoded_params_hex, 'hex').toString('base64'))
    })