build:
	cp package-signer-wasm.json pkg/package.json
	cd ledger-filecoin-js && yarn install && yarn build
	rm -rf node_modules/
	yarn install
	yarn build
