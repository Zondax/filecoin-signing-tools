
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

module.exports = { UnknownProtocolIndicator, InvalidPayloadLength };
