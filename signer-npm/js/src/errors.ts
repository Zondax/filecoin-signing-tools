export class UnknownProtocolIndicator extends Error {
  constructor(...args: any[]) {
    super(...args)
    this.message = 'Unknown protocol indicator byte.'
  }
}

export class InvalidPayloadLength extends Error {
  constructor(...args: any[]) {
    super(...args)
    this.message = 'Invalid payload length.'
  }
}

export class InvalidNamespace extends Error {
  constructor(...args: any[]) {
    super(...args)
    this.message = 'Invalid namespace.'
  }
}

export class InvalidSubAddress extends Error {
  constructor(...args: any[]) {
    super(...args)
    this.message = 'Invalid subAddress.'
  }
}

export class ProtocolNotSupported extends Error {
  constructor(protocolName: string, ...args: any[]) {
    super(...args)
    this.message = `${protocolName} protocol not supported.`
  }
}

export class InvalidChecksumAddress extends Error {
  constructor(...args: any[]) {
    super(...args)
    this.message = `Invalid address (checksum not matching the payload).`
  }
}

export class InvalidPrivateKeyFormat extends Error {
  constructor(...args: any[]) {
    super(...args)
    this.message = 'Private key need to be an instance of Buffer or a base64 string.'
  }
}
