/* eslint-disable no-console */
import blake from 'blakejs'
import { expect, test } from './jest'

test('blake2b', async () => {
  const result = blake.blake2b('zondax')
  expect(Buffer.from(result).toString('hex')).toEqual(
    'e5b1462ceb3a38e53db5a9a271f70d9fb224815bd27425e3d2cba603efb41dc840c0d5314b5dc1cc54f3583bfe7fd891ba22d821741a87a57ceca22f9a08f07c',
  )
})
