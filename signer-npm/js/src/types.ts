export type TransactionRaw = {
  To: string
  From: string
  Nonce: number
  Value: string
  GasLimit: number
  GasFeeCap: string
  GasPremium: string
  Method: number
  Params: string
}

export type Signature = {
  Data: string
  Type: number
}

export type SignedMessage = {
  Signature: Signature
}
