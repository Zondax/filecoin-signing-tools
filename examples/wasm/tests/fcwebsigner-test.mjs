import * as assert from 'assert';
import {hello} from 'fcwebsigner';

test('Hello world', () => {
    assert.equal(hello(), 123);
});

test('Hello world fail', () => {
    assert.equal(hello(), 124);
});

test('Hello world good', () => {
    assert.equal(hello(), 123);
});
