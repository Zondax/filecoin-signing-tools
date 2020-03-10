# Filecoin Wasm ES modules


Example of ES module using wasm.

Also run test (without framework) in ES modules (no commonJS).

## NOTES

Be sure your `package.json` in `fcwasmsigner` look like this :
```
{
  "name": "fcwasmsigner",
  "collaborators": [
    "Zondax <info@zondax.ch>"
  ],
  "type": "module",
  "version": "0.1.0",
  "files": [
    "fcwasmsigner_bg.wasm",
    "fcwasmsigner.mjs",
    "fcwasmsigner.d.ts"
  ],
  "main": "fcwasmsigner.mjs",
  "types": "fcwasmsigner.d.ts",
  "sideEffects": "false"
}
```

And rename `fcwasmsigner.js` into `fcwasmsigner.mjs`.

Don't forget to link with the library for development :
```
yarn link fcwasmsigner
```


### Run tests

```
npm test
```
