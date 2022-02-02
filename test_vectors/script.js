const {encode, decode} = require('@ipld/dag-cbor')
const {CID} = require('multiformats')
const raw = require('multiformats/codecs/raw')
const {identity} = require('multiformats/hashes/identity')
const fs = require('fs')

async function main() {
    /* Multisig creation update */
    /*
        Use this to update multisig.json
    */

    let multisig_json = fs.readFileSync('./multisig.json')
    multisig_json = JSON.parse(multisig_json)

    const cbor_multisig_hex = "8a0042000155011eaf1c8a4bbfeeb0870b1745b1f57503470b711601430003e81a000f4240430009c4430009c402584a82d82a53000155000e66696c2f352f6d756c74697369675831848255011eaf1c8a4bbfeeb0870b1745b1f57503470b71165501dfe49184d46adc8f89d44638beb45f78fcad2590010000"

    const cbor_multisig = Buffer.from(cbor_multisig_hex, "hex")
    const encoded_params = decode(cbor_multisig)[9]
    const cid = decode(encoded_params)[0]

    // Change version when needed
    const multisig_hash = await identity.digest(Buffer.from('fil/7/multisig', 'utf-8'))
    const new_multisig_CID = CID.create(1, raw.code, multisig_hash)

    // I need to update encoded params too
    const multisig_encoded_params_hex = Buffer.from(encoded_params).toString('hex')
    let new_hex = multisig_encoded_params_hex.replace(Buffer.from(cid.bytes).toString('hex'), Buffer.from(new_multisig_CID.bytes).toString('hex'))

    multisig_json.create.message.params = Buffer.from(new_hex, 'hex').toString('base64')
    let new_cbor_hex = cbor_multisig_hex.replace(Buffer.from(cid.bytes).toString('hex'), Buffer.from(new_multisig_CID.bytes).toString('hex'))
    multisig_json.create.cbor = new_cbor_hex

    fs.writeFileSync('./multisig.json', JSON.stringify(multisig_json))


    /* Paymentchannel creation update */
    /*
        Use this to update payment_channel.json
    */
    let payment_channel_json = fs.readFileSync('./payment_channel.json')
    payment_channel_json = JSON.parse(payment_channel_json)

    const payment_channel_params_b64_bls = "gtgqWBkAAVUAFGZpbC80L3BheW1lbnRjaGFubmVsWEqCWDEDkwecz0UMcgWwqOxkoW5i9Z9hJ1kJsU6RpoTUrMbzIbTsQfRUMxPCBa5gAZ/snDBOVQElRUfDOAbbTJ6ACbjr2cTS5fIBgg=="
    const payment_channel_params_b64_secpk256k1 = "gtgqWBkAAVUAFGZpbC80L3BheW1lbnRjaGFubmVsWEqCVQElRUfDOAbbTJ6ACbjr2cTS5fIBglgxA5MHnM9FDHIFsKjsZKFuYvWfYSdZCbFOkaaE1KzG8yG07EH0VDMTwgWuYAGf7JwwTg=="

    const payment_channel_params_bls = Buffer.from(payment_channel_params_b64_bls, "base64")
    const encoded_params_payment_channel_bls = decode(payment_channel_params_bls)[0]

    const payment_channel_params_secp256k1 = Buffer.from(payment_channel_params_b64_secpk256k1, "base64")
    const encoded_params_payment_channel_secp256k1 = decode(payment_channel_params_secp256k1)[0]


    // Change version when needed
    const payment_channel_hash = await identity.digest(Buffer.from('fil/7/paymentchannel', 'utf-8'))
    const new_payment_channel_CID = CID.create(1, raw.code, payment_channel_hash)

    const encoded_params_bls_hex = Buffer.from(payment_channel_params_bls).toString('hex')
    let new_bls_hex = encoded_params_bls_hex.replace(Buffer.from(encoded_params_payment_channel_bls.bytes).toString('hex'), Buffer.from(new_payment_channel_CID.bytes).toString('hex'))

    payment_channel_json.creation.bls.message.params = Buffer.from(new_bls_hex, 'hex').toString('base64')

    const encoded_params_secp256k1_hex = Buffer.from(payment_channel_params_secp256k1).toString('hex')

    let new_secpk256k1_hex = encoded_params_secp256k1_hex.replace(Buffer.from(encoded_params_payment_channel_secp256k1.bytes).toString('hex'), Buffer.from(new_payment_channel_CID.bytes).toString('hex'))

    payment_channel_json.creation.secp256k1.message.params = Buffer.from(new_secpk256k1_hex, 'hex').toString('base64')

    fs.writeFileSync('./payment_channel.json', JSON.stringify(payment_channel_json))
}

main()