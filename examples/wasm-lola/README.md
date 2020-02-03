# Filecoin Wasm ES modules


Example of ES module using wasm.

Also run test (without framework) in ES modules (no commonJS).

## NOTES

Be sure your `package.json` in `fcwebsigner` look like this :
```
{
  "name": "fcwebsigner",
  "collaborators": [
    "Zondax <info@zondax.ch>"
  ],
  "type": "module",
  "version": "0.1.0",
  "files": [
    "fcwebsigner_bg.wasm",
    "fcwebsigner.mjs",
    "fcwebsigner.d.ts"
  ],
  "main": "fcwebsigner.mjs",
  "types": "fcwebsigner.d.ts",
  "sideEffects": "false"
}
```

And rename `fcwebsigner.js` into `fcwebsigner.mjs`.

Don't forget to link with the library for development :
```
yarn link fcwebsigner
```


### Run tests

```
npm test
```
