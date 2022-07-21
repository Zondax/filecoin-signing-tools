import "./shim"

import { StatusBar } from 'expo-status-bar'
import { useEffect, useState } from 'react'
import { Button, StyleSheet, Text, TextInput, View } from 'react-native'
// @ts-ignore
import { generateMnemonic, keyDerive } from '@zondax/filecoin-signing-tools/js'

export default function App() {
  const [mnemonic, setMnemonic] = useState(generateMnemonic())
  const [derivationPath, setDerivationPath] = useState("m/44'/461'/0/0/1")
  const [dpInvalid, setDpInvalid] = useState(false)
  const [account, setAccount] = useState({ private_base64: '', address: '' })

  useEffect(() => {
    try {
      setAccount(keyDerive(mnemonic, derivationPath, ''))
    } catch (e) {
      console.log(e)
    }
  }, [mnemonic, derivationPath])

  return (
    <View style={styles.container}>
      <Text>
        Mnemonic Seed:
        <br />
      </Text>
      <TextInput
        // @ts-ignore
        style={styles.textInput}
        onChange={e => {
          setMnemonic(e.nativeEvent.text)
        }}
        value={mnemonic}
      />
      <Text>
        Derivation path:
        <br />
      </Text>
      <TextInput
        // @ts-ignore
        style={styles.textInput}
        onChange={e => {
          setDerivationPath(e.nativeEvent.text)
        }}
        value={derivationPath}
      />
      <Text>
        Address:
        <br />
        {account.address}
      </Text>

      <Text>
        KeyFile (to add account in Lotus):
        <br />
        {Buffer.from(`{"Type":"secp256k1","PrivateKey":"${account.private_base64}"}`).toString('hex')}
      </Text>
      <Button
        title="Refresh"
        color="#454545"
        onPress={() => {
          setMnemonic(generateMnemonic())
          setDerivationPath("m/44'/461'/0/0/0")
          console.log('Refresh')
        }}
      />
      <StatusBar style="auto" />
    </View>
  )
}

const styles = StyleSheet.create({
  textInput: {
    width: '400px',
    border: '1px solid black',
    borderRadius: 3,
    fontSize: '16px',
  },
  container: {
    flex: 1,
    backgroundColor: '#fff',
    rowGap: '1rem',
    alignItems: 'center',
    justifyContent: 'center',
  },
})
