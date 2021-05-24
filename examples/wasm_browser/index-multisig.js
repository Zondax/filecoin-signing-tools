import * as wasm from '@zondax/filecoin-signing-tools'

function log(text) {
  document.getElementById('output').innerHTML += text + '\n'
}

log('<h2>[wasm.create_multisig_with_fee]</h2>')

const multisig_create = {
  "constructor_params": {
    "signers": ["t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba", "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy"],
    "num_approvals_threshold": 1,
    "unlock_duration": 0,
    "start_epoch": 0
  },
  "message": {
    "to": "t01",
    "from": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
    "nonce": 1,
    "value": "1000",
    "gaslimit": 1000000,
    "gasfeecap": "2500",
    "gaspremium": "2500",
    "method": 2,
    "params": "gtgqUwABVQAOZmlsLzQvbXVsdGlzaWdYMYSCVQEerxyKS7/usIcLF0Wx9XUDRwtxFlUB3+SRhNRq3I+J1EY4vrRfePytJZABAAA="
  },
  "cbor": "8a0042000155011eaf1c8a4bbfeeb0870b1745b1f57503470b711601430003e81a000f4240430009c4430009c402584a82d82a53000155000e66696c2f342f6d756c74697369675831848255011eaf1c8a4bbfeeb0870b1745b1f57503470b71165501dfe49184d46adc8f89d44638beb45f78fcad2590010000"
}

console.log('About to call wasm.createMultisigWithFee():')
let create_multisig_transaction = wasm.createMultisigWithFee(
  multisig_create.message.from,
  multisig_create.constructor_params.signers,
  multisig_create.message.value,
  multisig_create.constructor_params.num_approvals_threshold,
  multisig_create.message.nonce,
  multisig_create.constructor_params.unlock_duration.toString(),
  multisig_create.constructor_params.start_epoch.toString(),
  multisig_create.message.gaslimit.toString(),
  multisig_create.message.gasfeecap,
  multisig_create.message.gaspremium,
)
console.log('Done calling wasm.createMultisigWithFee()')

log(`create_multisign_tx = ${JSON.stringify(create_multisig_transaction, 0, 4)}`)

