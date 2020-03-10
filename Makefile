
deps_wasm:
	cargo install wasm-pack --version 0.8.1 --force

build_wasm:
	rm -rf fcwasmsigner/pkg/
	wasm-pack build fcwasmsigner/
	# temporary workaround
	cp package-fcwasmsigner.json fcwasmsigner/pkg/package.json
	cp fcwasmsigner/pkg/fcwasmsigner.js fcwasmsigner/pkg/fcwasmsigner.mjs

link_wasm:
	cd fcwasmsigner/pkg && yarn link
	cd examples/wasm && yarn link "fcwasmsigner"

test_wasm_unit:
	wasm-pack test --firefox --chrome --headless ./fcwasmsigner

test_wasm_integration:
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
