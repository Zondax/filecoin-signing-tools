
deps_wasm:
	cargo install wasm-pack --version 0.8.1

build_wasm:
	rm -rf fcwebsigner/pkg/
	wasm-pack build --no-typescript --target nodejs fcwebsigner/
	# temporary workaround to support ESM module and browser without bundler magic
	wasm-pack build --no-typescript --target browser --out-dir pkg/browser fcwebsigner/
	cp package-fcwebsigner.json fcwebsigner/pkg/package.json

link_wasm:
	cd fcwebsigner/pkg && yarn link
	cd examples/wasm && yarn link "fcwebsigner"

test_wasm:
	cd examples/wasm && yarn run test:integration

deps: deps_wasm
	cargo install cargo-audit
	cargo install cargo-tree
	cargo install cargo-license
	cargo install cargo-outdated
	cargo install sccache
	echo "Remember to add export RUSTC_WRAPPER=sccache to your environment."

checks:
	cargo fmt -- --check
	cargo clippy --all-features
	cargo audit

hooks:
	git config core.hooksPath .githooks

# prepreprocess circleci config so it can be ran locally
# Usage example:
# make ci JOB=test_service
ci:
	circleci config process .circleci/config.yml > .circleci/tmp.yml
	circleci build -c .circleci/tmp.yml --job ${JOB}
