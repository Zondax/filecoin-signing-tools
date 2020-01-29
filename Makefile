deps:
	curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

build_wasm:
	wasm-pack build fcwebsigner/

link_wasm:
	cd fcwebsigner/pkg && yarn link
	cd examples/wasm && yarn link "fcwebsigner"

test_wasm:
	cd examples/wasm && yarn run test:integration
