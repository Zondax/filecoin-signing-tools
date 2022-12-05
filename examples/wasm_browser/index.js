import * as wasm from '@zondax/filecoin-signing-tools'
import * as js from '@zondax/filecoin-signing-tools/js'

function log(text) {
  document.getElementById('output').innerHTML += text + '\n'
}

/////////////////////////////////
// Generate Mnemonic

let mnemonic = wasm.generateMnemonic()
log('<h2>[wasm.mnemonic_generate]</h2>' + mnemonic)
log('mnemonic')

/////////////////////////////////
// Derive key

let key = wasm.keyDerive(mnemonic, "m/44'/461'/0/0/0", '')

log('<h2>[wasm.key_derive]</h2>')
log(`<b>address      </b> ${key.address}`)
log(`<b>public  key  </b> ${key.public_hexstring}`)
log(`<b>private key  </b> ${key.private_hexstring}`)
log(`<b>public array </b> ${key.public_raw}`)
log(`<b>private array</b> ${key.private_raw}`)
log(`<b>public base64</b> ${key.public_base64}`)
log(`<b>private base64</b> ${key.private_base64}`)

/////////////////////////////////
// Recover key

let recovered_key = wasm.keyRecover(Buffer.from('6a1a68774457742a8bc69db5491df5ae7677687d49e1003a78e2d60959d5f7a7', 'hex'))

log('<h2>[wasm.key_recover]</h2>')
log(`<b>address      </b> ${recovered_key.address}`)
log(`<b>public  key  </b> ${recovered_key.public_hexstring}`)
log(`<b>private key  </b> ${recovered_key.private_hexstring}`)
log(`<b>public array </b> ${recovered_key.public_raw}`)
log(`<b>private array</b> ${recovered_key.private_raw}`)

/////////////////////////////////
// Sign transaction

log('<h2>[wasm.sign_transaction]</h2>')

const unsigned_tx = {
  to: 't17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy',
  from: key.address,
  nonce: 1,
  value: '100000',
  gasprice: '2500',
  gaslimit: 25000,
  gaspremium: '2500',
  gasfeecap: '2500',
  method: 4,
  params: '',
}

console.log('About to call wasm.transactionSignLotus():')
wasm.transactionSignLotus(unsigned_tx, key.private_raw)
console.log('Done calling wasm.transactionSignLotus()')

log(`unsigned_tx = ${JSON.stringify(unsigned_tx, 0, 4)}`)

let signed_tx = wasm.transactionSign(unsigned_tx, key.private_raw)

log('\n...sign...\n')
log(`signed_tx = ${JSON.stringify(signed_tx, 0, 4)}`)

// PURE JS LIB

/////////////////////////////////
// Generate Mnemonic

mnemonic = js.generateMnemonic()
log('<h2>[js.mnemonic_generate]</h2>' + mnemonic)
log('mnemonic')

/////////////////////////////////
// Validate Address

let isValid_1 = js.validateAddressAsString('t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy')
let isValid_2 = js.validateAddressAsString('t76uoq6tp427uzv7fztccsnn64iwotfrristwprzz')
log('<h2>[js.validateAddressAsString]</h2>')
log(`<b>t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy      </b> ${isValid_1}`)
log(`<b>t76uoq6tp427uzv7fztccsnn64iwotfrristwprzz      </b> ${isValid_2}`)

isValid_1 = js.validateAddressAsBytes(Buffer.from('01fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855', 'hex'))
isValid_2 = js.validateAddressAsBytes(Buffer.from('07fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62822', 'hex'))
log('<h2>[js.validateAddressAsBytes]</h2>')
log(`<b>01fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855      </b> ${isValid_1}`)
log(`<b>07fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62822      </b> ${isValid_2}`)

/////////////////////////////////
// Derive key

key = js.keyDerive(mnemonic, "m/44'/461'/0/0/0", '')

log('<h2>[js.key_derive]</h2>')
log(`<b>address      </b> ${key.address}`)
log(`<b>public  key  </b> ${key.public_hexstring}`)
log(`<b>private key  </b> ${key.private_hexstring}`)
log(`<b>public array </b> ${key.public_raw}`)
log(`<b>private array</b> ${key.private_raw}`)
log(`<b>public base64</b> ${key.public_base64}`)
log(`<b>private base64</b> ${key.private_base64}`)

/////////////////////////////////
// Recover key

recovered_key = js.keyRecover(Buffer.from('6a1a68774457742a8bc69db5491df5ae7677687d49e1003a78e2d60959d5f7a7', 'hex'))

log('<h2>[js.key_recover]</h2>')
log(`<b>address      </b> ${recovered_key.address}`)
log(`<b>public  key  </b> ${recovered_key.public_hexstring}`)
log(`<b>private key  </b> ${recovered_key.private_hexstring}`)
log(`<b>public array </b> ${recovered_key.public_raw}`)
log(`<b>private array</b> ${recovered_key.private_raw}`)

/////////////////////////////////
// Sign transaction

log('<h2>[js.sign_transaction]</h2>')

console.log('About to call js.transactionSignLotus():')
js.transactionSignLotus(unsigned_tx, key.private_raw)
console.log('Done calling js.transactionSignLotus()')

log(`unsigned_tx = ${JSON.stringify(unsigned_tx, 0, 4)}`)

signed_tx = js.transactionSign(unsigned_tx, key.private_raw)

log('\n...sign...\n')
log(`signed_tx = ${JSON.stringify(signed_tx, 0, 4)}`)
