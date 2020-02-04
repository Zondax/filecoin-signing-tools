deps:
	#curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
	cargo install wasm-pack --version 0.8.1

build_wasm:
	wasm-pack build fcwebsigner/
	cp package-fcwebsigner.json fcwebsigner/pkg/package.json
	cp fcwebsigner/pkg/fcwebsigner.js fcwebsigner/pkg/fcwebsigner.mjs

link_wasm:
	cd fcwebsigner/pkg && yarn link
	cd examples/wasm && yarn link "fcwebsigner"

test_wasm:
	cd examples/wasm && yarn run test:integration
