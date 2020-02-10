
deps_wasm:
	cargo install wasm-pack --version 0.8.1

build_wasm:
	rm -rf fcwebsigner/pkg/
	wasm-pack build fcwebsigner/
	# temporary workaround
	cp package-fcwebsigner.json fcwebsigner/pkg/package.json
	cp fcwebsigner/pkg/fcwebsigner.js fcwebsigner/pkg/fcwebsigner.mjs

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

ci:
	# prepreprocess
	circleci config process .circleci/config.yml > .circleci/tmp.yml
	circleci local execute -c .circleci/tmp.yml
