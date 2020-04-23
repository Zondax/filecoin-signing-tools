# Using with ledger

This library can also help you to connect to a ledger device.

## DeviceSession

The `DeviceSession` class is an utility class. It will hold the connection with a device (`ledger` or `trezor` <- not yet supported) for you. It will need to be passed to functions that need device (generally the function name will have `WithDevice` in it).

You can also use `DeviceEnum.LEDGER` or `DeviceEnum.TREZOR` as an argument for the constructor.

```javascript
import {DeviceSession, DeviceEnum} from '@zondax/filecoin-signer';

const session = new DeviceSession(DeviceEnum.LEDGER);
```

## API

Hardware supported functionalities.

### keyRetrieveFromDevice

Get the public key information from a device using a given path.

Arguments:
* **path**: the BIP44 path as a string (e.g "m/44'/461'/0/0/1");
* **session**: the sesssion that hold the connection with the device (see [DeviceSession](#DeviceSession));


```javascript
import { DeviceSession, DeviceEnum, keyRetrieveFromDevice } from '@zondax/filecoin-signer';

const session = new DeviceSession(DeviceEnum.LEDGER);

const path = "m/44'/461'/0/0/1";

const keys = await keyRetrieveFromDevice(path, session);

console.log(keys);
```

### transactionSignWithDevice

Sign the transaction using a device using a given path. Return a ready to send transaction through the [JSON RPC service](/jsonrpc/). However it will not work with lotus json rpc service.

Arguments:
* **transaction**: the filecoin transaction to sign;
* **path**: the BIP44 path as a string (e.g "m/44'/461'/0/0/1");
* **session**: the sesssion that hold the connection with the device (see [DeviceSession](#DeviceSession));

```javascript
import { DeviceSession, DeviceEnum, transactionSignWithDevice } from '@zondax/filecoin-signer';

const session = new DeviceSession(DeviceEnum.LEDGER);

const transaction = {
    "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    "from": "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
    "nonce": 1,
    "value": "100000",
    "gasprice": "2500",
    "gaslimit": "25000",
    "method": 0,
    "params": ""
};

const path = "m/44'/461'/0/0/1";

const signedTransaction = await transactionSignWithDevice(transaction, path, session);

console.log(signedTransaction);
```

### transactionSignRawWithDevice

Sign the transaction using a device using a given path. Return only the signature of the transaction.

Arguments:
* **transaction**: the filecoin transaction to sign;
* **path**: the BIP44 path as a string (e.g "m/44'/461'/0/0/1");
* **session**: the sesssion that hold the connection with the device (see [DeviceSession](#DeviceSession));

```javascript
import { DeviceSession, DeviceEnum, transactionSignRawWithDevice } from '@zondax/filecoin-signer';

const session = new DeviceSession(DeviceEnum.LEDGER);

const transaction = {
    "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    "from": "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
    "nonce": 1,
    "value": "100000",
    "gasprice": "2500",
    "gaslimit": "25000",
    "method": 0,
    "params": ""
};

const path = "m/44'/461'/0/0/1";

const signature = await transactionSignRawWithDevice(transaction, path, session);

console.log(signature);
```
