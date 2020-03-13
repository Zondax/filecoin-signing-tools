import * as wasm from "@zondax/filecoin-signer-wasm";

function log(text) {
  document.getElementById("output").innerHTML += text + "\n";
}

/////////////////////////////////
// Generate Mnemonic

let mnemonic = wasm.mnemonic_generate();
log("<h2>[wasm.mnemonic_generate]</h2>" + mnemonic);
log("mnemonic");

/////////////////////////////////
// Derive key

let key = wasm.key_derive(mnemonic, "m/44'/461'/0/0/0");

log("<h2>[wasm.key_derive]</h2>");
log(`<b>address      </b> ${key.address}`);
log(`<b>public  key  </b> ${key.public_hexstring}`);
log(`<b>private key  </b> ${key.private_hexstring}`);
log(`<b>public array </b> ${key.public_raw}`);
log(`<b>private array</b> ${key.private_raw}`);

/////////////////////////////////
// Recover key

let recovered_key = wasm.key_recover("6a1a68774457742a8bc69db5491df5ae7677687d49e1003a78e2d60959d5f7a7");

log("<h2>[wasm.key_recover]</h2>");
log(`<b>address      </b> ${recovered_key.address}`);
log(`<b>public  key  </b> ${recovered_key.public_hexstring}`);
log(`<b>private key  </b> ${recovered_key.private_hexstring}`);
log(`<b>public array </b> ${recovered_key.public_raw}`);
log(`<b>private array</b> ${recovered_key.private_raw}`);

/////////////////////////////////
// Sign transaction

log("<h2>[wasm.sign_transaction]</h2>");

const unsigned_tx = {
  "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
  "from": key.address,
  "nonce": 1,
  "value": "100000",
  "gasprice": "2500",
  "gaslimit": "25000",
  "method": 0,
  "params": ""
};

log(`unsigned_tx = ${JSON.stringify(unsigned_tx, 0, 4)}`);

let signed_tx_str = wasm.transaction_sign(JSON.stringify(unsigned_tx), key.private_hexstring);

let signed_tx = JSON.parse(signed_tx_str);
log("\n...sign...\n");
log(`signed_tx = ${JSON.stringify(signed_tx, 0, 4)}`);
