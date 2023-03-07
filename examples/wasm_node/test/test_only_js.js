import * as filecoin_signer from '@zondax/filecoin-signing-tools/js'
import assert from 'assert'

describe('validateAddressAsString', function () {
  it('it should validate the f4 address', function () {
    const result = filecoin_signer.validateAddressAsString('t410f3otfsuz5pkc6ogzed6ehuz7ie2j4euzfkfzw4hy')

    assert(result)
  })
  it('it should not validate the address', function () {
    const result = filecoin_signer.validateAddressAsString('t411f3otfsuz5pkc6ogzed6ehuz7ie2j4euzfkfzw4hy')

    assert(!result)
  })
})
