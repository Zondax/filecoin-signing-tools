const filecoin_signer = require('@zondax/filecoin-signing-tools');
const bip39 = require('bip39');
const bip32 = require('bip32');
const axios = require('axios');
const {getDigest} = require('./test/utils');
const secp256k1 = require('secp256k1');
const assert = require('assert');
const cbor = require("ipld-dag-cbor").util;

const URL = process.env.URL
const TOKEN = process.env.TOKEN

const VOUCHER_SIGNER = "8VcW07ADswS4BV2cxi5rnIadVsyTDDhY1NfDH19T8Uo="
const privateKeyBase64 = "YbDPh1vq3fBClzbiwDt6WjniAdZn8tNcCwcBO2hDwyk="
const privateKey = Buffer.from(privateKeyBase64, 'base64')

const headers = { "Authorization": `Bearer ${TOKEN}` }

const skip = true

async function init() {
  /* Prepare node for when you start with a fresh devnet node */
  
    /* Import private key */
    response = await axios.post(URL, {
      jsonrpc: "2.0",
      method: "Filecoin.WalletImport",
      id: 1,
      params: [{ Type: "secp256k1", PrivateKey: privateKeyBase64}]
    }, {headers})

    console.log(response.data)

    /* Get miner address with funds */
    response = await axios.post(URL, {
      jsonrpc: "2.0",
      method: "Filecoin.WalletList",
      id: 1,
      params: []
    }, {headers})

    let address
    for (i in response.data.result) {
      if (response.data.result[i].startsWith("t3")) {
        address = response.data.result[i]
      }
    }
    console.log(address)

    /* Get nonce */

    let nonce = await getNonce(address)

    response = await axios.post(URL, {
      jsonrpc: "2.0",
      method: "Filecoin.WalletSignMessage",
      id: 1,
      params: [address, {
        From: address,
        To: "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy",
        Nonce: nonce,
        GasPremium: "2500",
        GasFeeCap: "2500",
        GasLimit: 2500000,
        Method: 0,
        Value: "10000000000000",
        Params: ""
      }]
    }, {headers})

    console.log(response.data)
    let signedMessage = response.data.result

    /* Send signed tx */

    let result = await sendSignedMessage(signedMessage)

    console.log(result)
    
    /* Get nonce */
    nonce = await getNonce(address)

    response = await axios.post(URL, {
      jsonrpc: "2.0",
      method: "Filecoin.WalletSignMessage",
      id: 1,
      params: [address, {
        From: address,
        To: "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
        Nonce: nonce,
        GasFeeCap: "2500",
        GasPremium: "2500",
        GasLimit: 2500000,
        Method: 0,
        Value: "10000000000000",
        Params: ""
      }]
    }, {headers})

    console.log(response.data)
    signedMessage = response.data.result

    /* Send signed tx */

    result = await sendSignedMessage(signedMessage)

    console.log(result)
}

async function getNonce(address) {
  /* Get Nonce */
  let response = await axios.post(URL, {
    jsonrpc: "2.0",
    method: "Filecoin.MpoolGetNonce",
    id: 1,
    params: [address]
  }, {headers})

  return response.data.result
}

async function getGasEstimation(message) {  
  /* Gas Estimation */
  let response = await axios.post(URL, {
    jsonrpc: "2.0",
    method: "Filecoin.GasEstimateMessageGas",
    id: 1,
    params: [message, {MaxFee: "0"}, null]
  }, {headers})
    
  return response.data
}

async function sendSignedMessage(signedMessage) {
  /*  Send signed tx */
  let response = await axios.post(URL, {
    jsonrpc: "2.0",
    method: "Filecoin.MpoolPush",
    id: 1,
    params: [signedMessage]
  }, { headers })

  let cid = response.data.result

  /* Wait for message */

  response = await axios.post(URL, {
    jsonrpc: "2.0",
    method: "Filecoin.StateWaitMsg",
    id: 1,
    params: [cid, null]
  }, { headers })

  return response.data
}

async function main () {
  let response
  var PCH
  
  if (!skip) {
    await init()
  }

  /* Recover address */
  console.log("##### RECOVER ADDRESS #####")
  
  let recoveredKey = filecoin_signer.keyRecover(privateKeyBase64, true);

  console.log(recoveredKey.address)
  
  /* Get nonce */
  console.log("##### GET NONCE #####")

  nonce = await getNonce(recoveredKey.address)

  /* Create payment channel */
  
  console.log("##### CREATE PAYMENT CHANNEL #####")
  
  let create_pymtchan = filecoin_signer.createPymtChan(recoveredKey.address, "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba", "10000000000", nonce, "0", "0", "0")
  
  create_pymtchan = await getGasEstimation(create_pymtchan)
  
  if ('result' in create_pymtchan) {
    create_pymtchan = create_pymtchan.result
  } else {
    assert(create_pymtchan.error)
  }
  console.log(create_pymtchan)
  
  signedMessage = JSON.parse(filecoin_signer.transactionSignLotus(create_pymtchan, privateKey))
  
  console.log(signedMessage)
  
  /* Send payment channel creation message */
  
  console.log("##### SEND PAYMENT CHANNEL #####")
  
  result = await sendSignedMessage(signedMessage)

  console.log(result)
  PCH = result.result.ReturnDec.IDAddress

  console.log(PCH)
  let PAYMENT_CHANNEL_ADDRESS = "t01010"
  if (PCH !== undefined) {
    PAYMENT_CHANNEL_ADDRESS = PCH
  }
  
  /* Create Voucher */
  
  console.log("##### CREATE VOUCHER #####")

  let voucher = filecoin_signer.createVoucher(PAYMENT_CHANNEL_ADDRESS, BigInt(0), BigInt(0), "100000", BigInt(0), BigInt(1), BigInt(0))
  
  console.log(voucher)
  
  /* Recover address */
  console.log("##### RECOVER ADDRESS #####")
  
  recoveredKey = filecoin_signer.keyRecover(privateKeyBase64, true);

  console.log(recoveredKey.address)
  
  /* Sign Voucher */
  
  console.log("##### SIGN VOUCHER #####")

  let signedVoucher = filecoin_signer.signVoucher(voucher, VOUCHER_SIGNER)
  
  console.log(signedVoucher)
  
  /* Verify voucher signature */
  
  assert(filecoin_signer.verifyVoucherSignature(signedVoucher, "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"))
  
  /*  Create Voucher 2 */
  
  console.log("##### CREATE VOUCHER 2 #####")

  let voucher2 = filecoin_signer.createVoucher(PAYMENT_CHANNEL_ADDRESS, BigInt(0), BigInt(0), "200000", BigInt(0), BigInt(2), BigInt(0))
  
  console.log(voucher2)
  
  /* Sign Voucher 2 */

  console.log("##### SIGN VOUCHER 2 #####")

  let signedVoucher2 = filecoin_signer.signVoucher(voucher2, VOUCHER_SIGNER)
  
  console.log(signedVoucher2)
  
  assert(filecoin_signer.verifyVoucherSignature(signedVoucher2, "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"))
  
  let tmp = cbor.deserialize(Buffer.from(signedVoucher2, 'base64'))[10]
  
  /* Create update voucher message */
  
  console.log("##### PREPARE UPDATE PAYMENT CHANNEL MESSAGE  #####")
  
  /* Get nonce */
  console.log("##### GET NONCE #####")

  nonce = await getNonce("t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy")

  let update_paych_message = filecoin_signer.updatePymtChan(PAYMENT_CHANNEL_ADDRESS, "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy", signedVoucher, nonce, "0", "0", "0")

  update_paych_message = await getGasEstimation(update_paych_message)
  
  if ('result' in update_paych_message) {
    update_paych_message = update_paych_message.result
  } else {
    assert(update_paych_message.error)
  }
  
  console.log(update_paych_message)

  signedMessage = JSON.parse(filecoin_signer.transactionSignLotus(update_paych_message, privateKeyBase64));
  
  console.log(signedMessage)
  
  console.log("##### SEND PAYMENT CHANNEL #####")
  
  result = await sendSignedMessage(signedMessage)

  console.log(result)
  
  /* Read payment channel state */
  
  console.log("##### READ PAYMENT CHANNEL STATE #####")
  
  response = await axios.post(URL, {
    jsonrpc: "2.0",
    method: "Filecoin.StateReadState",
    id: 1,
    params: [PAYMENT_CHANNEL_ADDRESS, null]
  }, { headers })

  console.log(response.data)
  
  /* Settle payment channel */
  
  /* Get nonce */
  console.log("##### GET NONCE #####")

  nonce = await getNonce("t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy")
  
  let settle_paych_message = filecoin_signer.settlePymtChan(PAYMENT_CHANNEL_ADDRESS, "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy", nonce, "0", "0", "0")

  settle_paych_message = await getGasEstimation(settle_paych_message)
  
  if ('result' in settle_paych_message) {
    settle_paych_message = settle_paych_message.result
  } else {
    assert(settle_paych_message.error)
  }
  console.log(settle_paych_message)

  signedMessage = JSON.parse(filecoin_signer.transactionSignLotus(settle_paych_message, privateKey));
  
  console.log(signedMessage)
  
  console.log("##### SETTLE PAYMENT CHANNEL #####")
  
  result = await sendSignedMessage(signedMessage)

  console.log(result)

  console.log("##### READ PAYMENT CHANNEL STATE #####")
  
  response = await axios.post(URL, {
    jsonrpc: "2.0",
    method: "Filecoin.StateReadState",
    id: 1,
    params: [PAYMENT_CHANNEL_ADDRESS, null]
  }, { headers })

  console.log(response.data)
  
  /* 
    IMPORTANT !!
    Wait until block `settling_at` block height reach before collect
  */

  /* Collect channel payment */
  
  console.log("##### COLLECT CHANNEL MESSAGE  #####")

  /* Get nonce */
  console.log("##### GET NONCE #####")

  nonce = await getNonce("t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy")
  
  let collect_paych_message = filecoin_signer.collectPymtChan(PAYMENT_CHANNEL_ADDRESS, "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy", nonce, "0", "0", "0")

  collect_paych_message = await getGasEstimation(collect_paych_message)

  /* Error on gas estimation call because not ready to collect. Expected behavior. */ 
  console.log(collect_paych_message)

  /*signedMessage = JSON.parse(filecoin_signer.transactionSignLotus(collect_paych_message, privateKey));
  
  console.log(signedMessage)
  
  console.log("##### COLLECTE PAYMENT CHANNEL #####")
  
  result = await sendSignedMessage(signedMessage)

  console.log(result)*/
  
}

main()
  .catch((error) => {
    console.log(error)
  })