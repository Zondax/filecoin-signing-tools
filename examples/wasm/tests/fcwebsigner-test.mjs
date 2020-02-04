import * as assert from 'assert';
import {hello, verify_signature} from 'fcwebsigner';

test('Hello world', () => {
    assert.equal(hello(), 123);
});

// FIXME: Disabled to avoid having CI issues. Move to a standard test runner
test('Hello world fail', () => {
    // assert.equal(hello(), 124);
});

test('Verify signature', () => {
  assert.equal(verify_signature(), false);
})
