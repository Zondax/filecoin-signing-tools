const config = require('./jest.config')

// Override default configuration
config.testMatch = ['**/__tests__/**/*.[jt]s?(x)', '**/?(*.)+(spec|test).[tj]s?(x)']

// eslint-disable-next-line no-console
console.log('RUNNING UNIT TESTS')

module.exports = config
