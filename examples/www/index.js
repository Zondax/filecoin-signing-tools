import * as wasm from "fcwasmsigner";
import * as bip32 from 'bip32';
import {getDigest} from './utils.js';

// Transaction
const transaction = {
  "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
  "from": "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
  "nonce": 1,
  "value": "100000",
  "gas_price": "2500",
  "gas_limit": "25000",
  "method": 0,
  "params": ""
};

// Root private key
const prv_root_key = "xprv9s21ZrQH143K49QgrAgAVELf6ue2tZNHYUc7yfj8JGZY9SpZ38u8EfhWi85GsA6grUeB36wXrbNTkjX9EfGP1ybbPRG4sdP2EPfY1SZ2BF5";

// Show on html page
document.getElementById("transaction").innerHTML = JSON.stringify(transaction).split(',').join(',\n');
document.getElementById("private_key").innerHTML = prv_root_key;

/////////////////////////////////
//
//        Generate Mnemonic
//
/////////////////////////////////

// Get mnemonic
let mnemonic = wasm.key_generate_mnemonic();
console.log(mnemonic);

/////////////////////////////////
//
//        Sign transaction
//
/////////////////////////////////

// Get derived private key
let node = bip32.fromBase58(prv_root_key);
let child = node.derivePath("m/44'/461'/0/0/0");

let signature = wasm.sign_transaction(JSON.stringify(transaction), child.privateKey.toString('hex'));

// Signature RSV !
document.getElementById("signature").innerHTML = signature;

/////////////////////////////////
//
//        Verify signature
//
/////////////////////////////////

// Encode to CBOR
let cbor_transaction = wasm.transaction_create(JSON.stringify(transaction));

let elt = document.getElementById("verify");

// Verify message
if (wasm.verify_signature(signature, cbor_transaction)) {
  elt.innerHTML = '✔ Signature valid';
} else {
  elt.innerHTML = '❌ Signature invalid';
}
