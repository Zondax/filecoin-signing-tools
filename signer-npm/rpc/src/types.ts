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
  Message: TransactionRaw
  Signature: Signature
}

export type RpcError = {
  error: {
    message: string
  }
}

export type GetNonceResponse =
  | {
      result: number
    }
  | RpcError

export type GasEstimationResponse =
  | {
      result: { GasFeeCap: string; GasPremium: string; GasLimit: number }
    }
  | RpcError

export type SendSignMessageResponse =
  | {
      ['/']: string
    }
  | {
      Message: { '/': string }
      Receipt: { ExitCode: number; Return: string; GasUsed: number }
      ReturnDec: string
      TipSet: { '/': string }[]
      Height: number
    }
  | RpcError

export type ReadStateResponse = { Balance: string; Code: { '/': string } } | RpcError
