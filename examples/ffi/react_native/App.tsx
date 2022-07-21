import "./shim"

import { StatusBar } from 'expo-status-bar'
import { useEffect, useState } from 'react'
import { Button, StyleSheet, Text, TextInput, View } from 'react-native'
// @ts-ignore
//import { generateMnemonic, keyDerive } from '@zondax/filecoin-signing-tools/js'

async function runWasm(){
    const buffer = Uint8Array.from([
        0x00,0x61,0x73,0x6D,0x01,0x00,0x00,0x00
        ,0x01,0x87,0x80,0x80,0x80,0x00,0x01,0x60
        ,0x02,0x7F,0x7F,0x01,0x7F,0x03,0x82,0x80
        ,0x80,0x80,0x00,0x01,0x00,0x07,0x87,0x80
        ,0x80,0x80,0x00,0x01,0x03,0x61,0x64,0x64
        ,0x00,0x00,0x0A,0x8D,0x80,0x80,0x80,0x00
        ,0x01,0x87,0x80,0x80,0x80,0x00,0x00,0x20
        ,0x00,0x20,0x01,0x6A,0x0B]);

    const res = await WebAssembly.instantiate(buffer)
    return res.instance.exports
}

export default function App() {
  const [mnemonic, setMnemonic] = useState("asdasdasd")
  const [derivationPath, setDerivationPath] = useState("m/44'/461'/0/0/1")
  const [dpInvalid, setDpInvalid] = useState(false)
  const [account, setAccount] = useState({ private_base64: '', address: '' })


  useEffect(() => {
      (async function test(){
          try {
              const res = await runWasm()
              setMnemonic(String(res.add(3, 5)))
          }catch (e){
              setMnemonic(e.stack)
          }
      })()
  }, [])

  return (
    <View style={styles.container}>
      <Text>
        Mnemonic Seed:{mnemonic}
      </Text>
      <Text>
        Derivation path:
      </Text>
      <Text>
        Address:
        {account.address}
      </Text>

      <Text>
        KeyFile (to add account in Lotus):
        {Buffer.from(`{"Type":"secp256k1","PrivateKey":"${account.private_base64}"}`).toString('hex')}
      </Text>
      <Button
        title="Refresh"
        color="#454545"
        onPress={() => {
          console.log('Refresh')
        }}
      />
      <StatusBar style="auto" />
    </View>
  )
}

const styles = StyleSheet.create({
  textInput: {
    width: "400px",
    border: "1px solid black",
    borderRadius: 3,
    fontSize: "16",
  },
  container: {
    flex: 1,
    backgroundColor: "#fff",
    rowGap: "1rem",
    alignItems: "center",
    justifyContent: "center",
  },
})

