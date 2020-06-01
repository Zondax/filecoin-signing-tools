class ExtendedKey {
  constructor(privateKey, publicKey, address) {
    this.publicKey = publicKey // Buffer
    this.privateKey = privateKey // Buffer
    this.address = address // String
  }

  get public_raw() {
    return this.publicKey.buffer
  }

  get private_raw() {
    return this.privateKey.buffer
  }

  get public_hexstring() {
    return this.publicKey.toString('hex')
  }

  get private_hexstring() {
    return this.privateKey.toString('hex')
  }

  get public_base64() {
    // REVIEW: will this work in browser ?
    return this.publicKey.toString('base64')
  }

  get private_base64() {
    // REVIEW: will this work in browser ?
    return this.privateKey.toString('base64')
  }
}

module.exports = ExtendedKey;
