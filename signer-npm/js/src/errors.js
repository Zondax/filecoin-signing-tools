class UnknownProtocolIndicator extends Error {
  constructor(...args) {
    super(...args);
    this.message = "Unknown protocol indicator byte.";
  }
}

class InvalidPayloadLength extends Error {
  constructor(...args) {
    super(...args);
    this.message = "Invalid payload length.";
  }
}

class ProtocolNotSupported extends Error {
  constructor(protocolName, ...args) {
    super(...args);
    this.message = `${protocolName} protocol not supported.`;
  }
}

class InvalidChecksumAddress extends Error {
  constructor(...args) {
    super(...args);
    this.message = `Invalid address (checksum not matching the payload).`;
  }
}

module.exports = {
  UnknownProtocolIndicator,
  InvalidPayloadLength,
  ProtocolNotSupported,
  InvalidChecksumAddress,
};
