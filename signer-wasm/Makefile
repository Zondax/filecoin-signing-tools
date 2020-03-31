build:
	cp pkg/filecoin_signer_wasm_bg.wasm pkg/src
	cp pkg/filecoin_signer_wasm.js pkg/src
	cp -rT ledger-filecoin-js/src pkg/src/ledger
	cp package-signer-wasm.json pkg/package.json
	cp lib/* pkg/src
	cd pkg && npm run build
