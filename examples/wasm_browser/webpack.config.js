const CopyWebpackPlugin = require('copy-webpack-plugin')
const path = require('path')
const fs = require('fs')

module.exports = {
  entry: './bootstrap.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'bootstrap.js',
  },
  mode: 'development',
  plugins: [
    new CopyWebpackPlugin(['index.html']),
  ],
  devServer: {
    https: true,
    key: fs.readFileSync('certs/server.key'),
    cert: fs.readFileSync('certs/server.cert'),
    ca: fs.readFileSync('certs/cert.pem'),
  },
}
