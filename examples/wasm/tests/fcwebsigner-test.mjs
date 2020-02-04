import * as assert from 'assert';
import {hello} from 'fcwebsigner';

test('Hello world', () => {
    assert.equal(hello(), 123);
});

// FIXME: Disabled to avoid having CI issues. Move to a standard test runner
test('Hello world fail', () => {
    // assert.equal(hello(), 124);
});
