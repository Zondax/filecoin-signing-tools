const bip32 = require('bip32');

const EXAMPLE_MNEMONIC = "equip will roof matter pink blind book anxiety banner elbow sun young";
const EXAMPLE_CBOR_TX = "8A005501FD1D0F4DFCD7E99AFCB99A8326B7DC459D32C62855011EAF1C8A4BBFEEB0870B1745B1F57503470B71160144000186A01961A84200014200010040".toLowerCase();
const EXAMPLE_ADDRESS_MAINNET = "f1rovwtiuo5ncslpmpjftzu5akswbgsgighjazxoi";
const EXAMPLE_TRANSACTION = {
    "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    "from": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
    "nonce": 1,
    "value": "100000",
    "gaslimit": 25000,
    "gasfeecap": "1",
    "gaspremium": "1",
    "method": 0,
    "params": ""
};

const EXAMPLE_TRANSACTION_MAINNET = {
    "to": "f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    "from": "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
    "nonce": 1,
    "value": "100000",
    "gaslimit": 25000,
    "gasfeecap": "1",
    "gaspremium": "1",
    "method": 0,
    "params": ""
};

const MASTER_KEY = "xprv9s21ZrQH143K49QgrAgAVELf6ue2tZNHYUc7yfj8JGZY9SpZ38u8EfhWi85GsA6grUeB36wXrbNTkjX9EfGP1ybbPRG4sdP2EPfY1SZ2BF5";
const MASTER_NODE = bip32.fromBase58(MASTER_KEY);

module.exports = { 
  EXAMPLE_MNEMONIC,
  EXAMPLE_CBOR_TX,
  EXAMPLE_ADDRESS_MAINNET,
  EXAMPLE_TRANSACTION,
  EXAMPLE_TRANSACTION_MAINNET,
  MASTER_KEY,
  MASTER_NODE,
};
