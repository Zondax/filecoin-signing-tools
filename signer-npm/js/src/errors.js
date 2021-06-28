class UnknownProtocolIndicator extends Error {
  constructor(...args) {
    super(...args)
    this.message = 'Unknown protocol indicator byte.'
  }
}

class InvalidPayloadLength extends Error {
  constructor(...args) {
    super(...args)
    this.message = 'Invalid payload length.'
  }
}

class ProtocolNotSupported extends Error {
  constructor(protocolName, ...args) {
    super(...args)
    this.message = `${protocolName} protocol not supported.`
  }
}

class InvalidChecksumAddress extends Error {
  constructor(...args) {
    super(...args)
    this.message = `Invalid address (checksum not matching the payload).`
  }
}

class InvalidPrivateKeyFormat extends Error {
  constructor(...args) {
    super(...args)
    this.message = 'Private key need to be an instance of Buffer or a base64 string.'
  }
}

module.exports = {
  UnknownProtocolIndicator,
  InvalidPayloadLength,
  ProtocolNotSupported,
  InvalidChecksumAddress,
  InvalidPrivateKeyFormat,
}
