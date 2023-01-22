import axios, { AxiosInstance } from 'axios'
import { GasEstimationResponse, GetNonceResponse, ReadStateResponse, SendSignMessageResponse, SignedMessage, TransactionRaw } from './types'

type Args = { url: string; token: string }

export default class FilecoinRPC {
  requester: AxiosInstance

  constructor(args: Args) {
    if (!('url' in args && 'token' in args)) {
      throw new Error('FilecoinRPC required an `url` and a `token` to communicate with the node.')
    }

    this.requester = axios.create({
      baseURL: args.url,
      headers: { Authorization: `Bearer ${args.token}` },
    })
  }

  async getNonce(address: string): Promise<GetNonceResponse> {
    let response = await this.requester.post('', {
      jsonrpc: '2.0',
      method: 'Filecoin.MpoolGetNonce',
      id: 1,
      params: [address],
    })

    return response.data
  }

  async sendSignedMessage(signedMessage: SignedMessage, skipStateWaitMsg?: boolean): Promise<SendSignMessageResponse> {
    let response = await this.requester.post('', {
      jsonrpc: '2.0',
      method: 'Filecoin.MpoolPush',
      id: 1,
      params: [signedMessage],
    })

    if ('error' in response.data) {
      throw new Error(response.data.error.message)
    }

    let cid = response.data.result

    if (skipStateWaitMsg) return cid

    response = await this.requester.post('', {
      jsonrpc: '2.0',
      method: 'Filecoin.StateWaitMsg',
      id: 1,
      params: [cid, 0, null, false],
    })

    return response.data
  }

  async getGasEstimation(message: TransactionRaw): Promise<GasEstimationResponse> {
    let response = await this.requester.post('', {
      jsonrpc: '2.0',
      method: 'Filecoin.GasEstimateMessageGas',
      id: 1,
      params: [message, { MaxFee: '0' }, null],
    })

    return response.data
  }

  async readState(address: string): Promise<ReadStateResponse> {
    let response = await this.requester.post('', {
      jsonrpc: '2.0',
      method: 'Filecoin.StateReadState',
      id: 1,
      params: [address, null],
    })

    return response.data
  }
}
