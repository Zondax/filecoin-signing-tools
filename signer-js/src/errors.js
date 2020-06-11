
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
    this.message = protocolName + " protocol not supported.";
  }
}


module.exports = { UnknownProtocolIndicator, InvalidPayloadLength, ProtocolNotSupported };
