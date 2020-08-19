const filecoin_signer = require('@zondax/filecoin-signing-tools');
const bip39 = require('bip39');
const bip32 = require('bip32');
const axios = require('axios');

const URL = "http://192.168.1.38:1234/rpc/v0"
const TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBbGxvdyI6WyJyZWFkIiwid3JpdGUiLCJzaWduIiwiYWRtaW4iXX0.2l5dql9PvaFPNY8_0UynbY0usJZ99dbIwpPUtaEDIYs"

const privateKeyBase64 = "YbDPh1vq3fBClzbiwDt6WjniAdZn8tNcCwcBO2hDwyk="
const privateKey = Buffer.from(privateKeyBase64, 'base64')

const headers = { "Authorization": `Bearer ${TOKEN}` }

const skip = true

async function main () {
  let response
  
  if (!skip) {
    
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

      let address = response.data.result[1]
      console.log(address)

      /* Get nonce */

      response = await axios.post(URL, {
        jsonrpc: "2.0",
        method: "Filecoin.MpoolGetNonce",
        id: 1,
        params: [address]
      }, {headers})

      console.log(response.data)
      let nonce = response.data.result

      response = await axios.post(URL, {
        jsonrpc: "2.0",
        method: "Filecoin.WalletSignMessage",
        id: 1,
        params: [address, {
          From: address,
          To: "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy",
          Nonce: nonce,
          GasPrice: "1",
          GasLimit: 1000000,
          Method: 0,
          Value: "100000000000",
          Params: ""
        }]
      }, {headers})

      console.log(response.data)
      let signedMessage = response.data.result

      /* Send signed tx */

      response = await axios.post(URL, {
        jsonrpc: "2.0",
        method: "Filecoin.MpoolPush",
        id: 1,
        params: [signedMessage]
      }, { headers })

      console.log(response.data)

      let cid = response.data.result

      /* Wait for message */

      response = await axios.post(URL, {
        jsonrpc: "2.0",
        method: "Filecoin.StateWaitMsg",
        id: 1,
        params: [cid, null]
      }, { headers })

      console.log(response.data)
      
      /* Get nonce */

      response = await axios.post(URL, {
        jsonrpc: "2.0",
        method: "Filecoin.MpoolGetNonce",
        id: 1,
        params: [address]
      }, {headers})

      console.log(response.data)
      nonce = response.data.result

      response = await axios.post(URL, {
        jsonrpc: "2.0",
        method: "Filecoin.WalletSignMessage",
        id: 1,
        params: [address, {
          From: address,
          To: "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
          Nonce: nonce,
          GasPrice: "1",
          GasLimit: 1000000,
          Method: 0,
          Value: "100000000000",
          Params: ""
        }]
      }, {headers})

      console.log(response.data)
      signedMessage = response.data.result

      /* Send signed tx */

      response = await axios.post(URL, {
        jsonrpc: "2.0",
        method: "Filecoin.MpoolPush",
        id: 1,
        params: [signedMessage]
      }, { headers })

      console.log(response.data)

      cid = response.data.result

      /* Wait for message */

      response = await axios.post(URL, {
        jsonrpc: "2.0",
        method: "Filecoin.StateWaitMsg",
        id: 1,
        params: [cid, null]
      }, { headers })

      console.log(response.data)
    
      /* Recover address */
      console.log("##### RECOVER ADDRESS #####")
      
      let recoveredKey = filecoin_signer.keyRecover(privateKeyBase64, true);

      console.log(recoveredKey.address)
      
      /* Get nonce */
      console.log("##### GET NONCE #####")

      response = await axios.post(URL, {
        jsonrpc: "2.0",
        method: "Filecoin.MpoolGetNonce",
        id: 1,
        params: [recoveredKey.address]
      }, {headers})

      console.log(response.data)
      nonce = response.data.result

      /* Create payment channel */
      
      console.log("##### CREATE PAYMENT CHANNEL #####")
      
      let create_pymtchan = filecoin_signer.createPymtChan(recoveredKey.address, "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba", "10000000000", nonce)
        
      signedMessage = JSON.parse(filecoin_signer.transactionSignLotus(create_pymtchan, privateKey));
      
      console.log(signedMessage)
      
      /* Send payment channel creation message */
      
      console.log("##### SEND PAYMENT CHANNEL #####")
      
      response = await axios.post(URL, {
        jsonrpc: "2.0",
        method: "Filecoin.MpoolPush",
        id: 1,
        params: [signedMessage]
      }, { headers })

      console.log(response.data)

      cid = response.data.result

      /* Wait for message */
      
      console.log("##### WAIT FOR PAYMENT CHANNEL STATE #####")

      response = await axios.post(URL, {
        jsonrpc: "2.0",
        method: "Filecoin.StateWaitMsg",
        id: 1,
        params: [cid, null]
      }, { headers })

      console.log(response.data)
  }

  
  /* Get status */
  let PAYMENT_CHANNEL_ADDRESS = "t01003"
  
  console.log("##### GET PAYMENT CHANNEL STATUS #####")

  response = await axios.post(URL, {
    jsonrpc: "2.0",
    method: "Filecoin.PaychStatus",
    id: 1,
    params: [PAYMENT_CHANNEL_ADDRESS]
  }, { headers })

  console.log(response.data)
  
  /* Create Voucher */
  
  console.log("##### CREATE VOUCHER #####")

  let voucher = filecoin_signer.createVoucher(BigInt(1234), BigInt(0), "100000", BigInt(0), BigInt(1), BigInt(1))
  
  console.log(voucher)
  
  /* Sign Voucher */
  
  console.log("##### SIGN VOUCHER #####")

  let signedVoucher = filecoin_signer.signVoucher(voucher, privateKeyBase64)
  
  console.log(signedVoucher)
  
  /*  Create Voucher 2 */
  
  console.log("##### CREATE VOUCHER 2 #####")

  let voucher2 = filecoin_signer.createVoucher(BigInt(1234), BigInt(0), "200000", BigInt(0), BigInt(2), BigInt(1))
  
  console.log(voucher2)
  
  /* Sign Voucher 2 */

  console.log("##### SIGN VOUCHER 2 #####")

  let signedVoucher2 = filecoin_signer.signVoucher(voucher2, privateKeyBase64)
  
  console.log(signedVoucher2)

  /* Create update voucher message */
  
  console.log("##### PREPARE UPDATE PAYMENT CHANNEL MESSAGE  #####")
  
  /* Get nonce */
  console.log("##### GET NONCE #####")

  response = await axios.post(URL, {
    jsonrpc: "2.0",
    method: "Filecoin.MpoolGetNonce",
    id: 1,
    params: ["t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy"]
  }, {headers})

  console.log(response.data)
  nonce = response.data.result
  
  let update_paych_message = filecoin_signer.updatePymtChan("t01003", "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy", signedVoucher, nonce)

  console.log(update_paych_message)

  signedMessage = JSON.parse(filecoin_signer.transactionSignLotus(update_paych_message, privateKey));
  
  console.log(signedMessage)
  
  console.log("##### SEND PAYMENT CHANNEL #####")
  
  response = await axios.post(URL, {
    jsonrpc: "2.0",
    method: "Filecoin.MpoolPush",
    id: 1,
    params: [signedMessage]
  }, { headers })

  console.log(response.data)

  cid = response.data.result

  /* Wait for message */
  
  console.log("##### WAIT FOR PAYMENT CHANNEL STATE #####")

  response = await axios.post(URL, {
    jsonrpc: "2.0",
    method: "Filecoin.StateWaitMsg",
    id: 1,
    params: [cid, null]
  }, { headers })

  console.log(response.data)
  
  /* Settle payment channel */
  
  /* Get nonce */
  console.log("##### GET NONCE #####")

  response = await axios.post(URL, {
    jsonrpc: "2.0",
    method: "Filecoin.MpoolGetNonce",
    id: 1,
    params: ["t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy"]
  }, {headers})

  console.log(response.data)
  nonce = response.data.result
  
  let update_paych_message = filecoin_signer.settlePymtChan("101003", "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy", signedVoucher, nonce)

  console.log(update_paych_message)

  signedMessage = JSON.parse(filecoin_signer.transactionSignLotus(update_paych_message, privateKey));
  
  console.log(signedMessage)
  
  console.log("##### SEND PAYMENT CHANNEL #####")
  
  response = await axios.post(URL, {
    jsonrpc: "2.0",
    method: "Filecoin.MpoolPush",
    id: 1,
    params: [signedMessage]
  }, { headers })

  console.log(response.data)

  cid = response.data.result

  /* Wait for message */
  
  console.log("##### WAIT FOR PAYMENT CHANNEL STATE #####")

  response = await axios.post(URL, {
    jsonrpc: "2.0",
    method: "Filecoin.StateWaitMsg",
    id: 1,
    params: [cid, null]
  }, { headers })

  console.log(response.data)
  
}

main()
  .catch((error) => {
    console.log(error)
  })