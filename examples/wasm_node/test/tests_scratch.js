/* eslint-disable no-console */
import * as bip32 from 'bip32'
import assert from 'assert'
import bip39 from 'bip39'
import * as utils from './utils.js'
import secp256k1 from 'secp256k1'

/* TODO: rename as a generate file and not test */

it('hex to base64', function() {
  const hex =
    '8855016055f878cce452b68cb0b78baaa8a683a7124b655501e14734e92a0aa6239432259006c3858f387dd475004800038d7ea4c68000420001430003e80040'
  const buf = Buffer.from(hex, 'hex')
  const out = buf.toString('base64')
  assert.strictEqual(out, 'iFUBYFX4eMzkUraMsLeLqqimg6cSS2VVAeFHNOkqCqYjlDIlkAbDhY84fdR1AEgAA41+pMaAAEIAAUMAA+gAQA==')
})

it('get testing keys', async function() {
  const testMnemonic = 'equip will roof matter pink blind book anxiety banner elbow sun young'

  const seed = await bip39.mnemonicToSeed(testMnemonic)
  console.log(seed.toString('hex'))

  const node = bip32.fromSeed(seed)
  const child = node.derivePath('44\'/1\'/0/0/0')

  console.log(`pubkey : ${child.publicKey.toString('hex')}`)
  console.log(`privkey : ${child.privateKey.toString('hex')}`)
  console.log(`privkey (base64) : ${child.privateKey.toString('base64')}`)

  const pk2 = secp256k1.publicKeyCreate(child.privateKey)
  console.log(`pubkey2: ${Buffer.from(pk2).toString('hex')}`)

  const expectedUncompressedKey =
    '0466f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b765c649056ba4a62292ae4e2ccdabd71b845d8fa0991c140f664d2978ac0972a'

  const pk3 = secp256k1.publicKeyCreate(child.privateKey, false)
  console.log(`pubkey3: ${Buffer.from(pk3).toString('hex')}`)
  assert.strictEqual(Buffer.from(pk3).toString('hex'), expectedUncompressedKey)
})

it('recover pubkey', function() {
  const signature = Buffer.from(
    'eabd5dddcbc8e38168ce1ef135fb3f35f0e5077ecdcd8b093d223af399e68f79788ff5ac99426a4f3dd976438ca6abd94e7bd7274a2f6b74d3451a341637f51301',
    'hex',
  )
  const message = Buffer.from('bb1b80a7c6d9ef890ca7a27a7fd4eb8d72faee7fdfde7f9bebc727bef8e4c5de', 'hex')

  const pubkey = secp256k1.ecdsaRecover(signature.slice(0, 64), signature[64], message, false)
  console.log(Buffer.from(pubkey).toString('hex'))
})

it('recover pubkey2', function() {
  const signature = Buffer.from(
    '66f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b55866912b1900bc253389c982187848699a0068ff9fd81b836642aa49991931100',
    'hex',
  )
  const expectedUncompressedKey =
    '0466f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b765c649056ba4a62292ae4e2ccdabd71b845d8fa0991c140f664d2978ac0972a'
  const expectedCompressedKey = '0266f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b'

  const message = Buffer.from('f98956833a086822f08c357aeb8500ed9f654b4d31e42cc78e1e5160d80459fe', 'hex')

  const pubkeyUncompressed = secp256k1.ecdsaRecover(signature.slice(0, 64), signature[64], message, false)
  console.log(Buffer.from(pubkeyUncompressed).toString('hex'))
  assert.strictEqual(Buffer.from(pubkeyUncompressed).toString('hex'), expectedUncompressedKey)

  const pubkeyCompressed = secp256k1.ecdsaRecover(signature.slice(0, 64), signature[64], message, true)
  console.log(Buffer.from(pubkeyCompressed).toString('hex'))
  assert.strictEqual(Buffer.from(pubkeyCompressed).toString('hex'), expectedCompressedKey)
})

it('verify signature', function() {
  const signature = Buffer.from(
    '66f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b41790398bdf0137adc836827a2d5d1f1d47188b0185897f5014a9619761909c801',
    'hex',
  )
  const pubkey = Buffer.from(
    '0466f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b765c649056ba4a62292ae4e2ccdabd71b845d8fa0991c140f664d2978ac0972a',
    'hex',
  )

  const digest = Buffer.from('0349ca6694262c6eae4f1a9a13e5e9bf8cb9e8122ea2684598f1c51350b68022', 'hex')
  assert(secp256k1.ecdsaVerify(signature.slice(0, 64), digest, pubkey))
})

it('verify signature 2', function() {
  const signature = Buffer.from(
    '66f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b41790398bdf0137adc836827a2d5d1f1d47188b0185897f5014a9619761909c801',
    'hex',
  )
  const pubkey = Buffer.from(
    '0466f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b765c649056ba4a62292ae4e2ccdabd71b845d8fa0991c140f664d2978ac0972a',
    'hex',
  )

  const digest = Buffer.from('0349ca6694262c6eae4f1a9a13e5e9bf8cb9e8122ea2684598f1c51350b68022', 'hex')
  assert(secp256k1.ecdsaVerify(signature.slice(0, 64), digest, pubkey))
})

it('Signing (used to generate signature in signer crate lib.rs test)', function() {
  const message = '89005501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855011eaf1c8a4bbfeeb0870b1745b1f57503470b71160144000186a0430009c41961a80040'
  const message_digest = utils.getDigest(Buffer.from(message, 'hex'))
  const prvkey = 'f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a'

  // Get hex signature in the format (R,S)
  let signature = secp256k1.ecdsaSign(message_digest, Buffer.from(prvkey, 'hex'))

  console.log(Buffer.from(signature.signature).toString('hex'))
  console.log(signature)
})

it('convert signature data to base64 ', function() {
  console.log(Buffer.from('06398485060ca2a4deb97027f518f45569360c3873a4303926fa6909a7299d4c55883463120836358ff3396882ee0dc2cf15961bd495cdfb3de1ee2e8bd3768e01', 'hex').toString('base64'))
})
