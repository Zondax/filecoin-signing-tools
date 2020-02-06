import * as assert from 'assert';
import {hello, verify_signature, key_generate, key_derive} from 'fcwebsigner';

test('Hello world', () => {
    assert.equal(hello(), 123);
});

// FIXME: Disabled to avoid having CI issues. Move to a standard test runner
test('Hello world fail', () => {
    // assert.equal(hello(), 124);
});

test('Key Generate', () => {

  // TODO
  let key = key_generate();

  console.log("Pubkey :", key.pubkey);
  console.log("Prvkey :", key.prvkey);

  assert.equal(key.pubkey, "Public key!")
})

test('Key Derive', () => {
  let keypair = key_derive("equip will roof matter pink blind book anxiety banner elbow sun young", "m/44'/161'/0/0/1");

  console.log("Pubkey :", keypair.pubkey);
  console.log("Prvkey :", keypair.prvkey);
})

test('Verify signature', () => {
  assert.equal(verify_signature(), false);
})
