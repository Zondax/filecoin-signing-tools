NPM_PACKAGE_NAME:="@zondax/filecoin-signing-tools"

build: build_npm

run_service:
	cargo run --manifest-path service/Cargo.toml -- start

install_wasmpack:
ifeq ($(SILENT),)
	@echo -n "Going to install wasm-pack in your system, are you sure ? [y/N] " && read ans && [ $${ans:-N} = y ]
endif
	curl -o /tmp/tmp.sh https://rustwasm.github.io/wasm-pack/installer/init.sh
	chmod +x /tmp/tmp.sh
	/tmp/tmp.sh -f
	cargo install wasm-pack --force --version 0.8.1
#	curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
#	cargo install wasm-pack

build_npm:
	yarn
	rm -rf signer-npm/pkg/
	wasm-pack build --no-typescript --target nodejs --out-dir pkg/nodejs  signer-npm/
	wasm-pack build --no-typescript --target browser --out-dir pkg/browser signer-npm/
	# For the pure js we need the node_modules folder when using `yarn link`
	cd signer-npm/js && yarn install && yarn lint
	cd signer-npm && make build
	cp signer-npm/README.md signer-npm/pkg/README.md

clean_npm:
	rm -rf examples/wasm_node/node_modules || true
	rm -rf examples/wasm_browser/node_modules || true

link_npm: build_npm
	cd signer-npm/pkg && yarn unlink  || true
	cd examples/wasm_node && yarn unlink $(NPM_PACKAGE_NAME) || true
	cd examples/wasm_browser && yarn unlink $(NPM_PACKAGE_NAME) || true

#	# Now use it in other places
	cd signer-npm/pkg && yarn link
	cd examples/wasm_node && yarn link $(NPM_PACKAGE_NAME) && yarn install
	cd examples/wasm_browser && yarn link $(NPM_PACKAGE_NAME)

test_npm_unit: build_npm
	#wasm-pack test --chrome --firefox --headless ./signer-npm
	wasm-pack test --firefox --headless ./signer-npm

# Rename because now we also test pure js lib
test_npm_node: link_npm
	cd examples/wasm_node && yarn test
	cd examples/wasm_node && yarn test:js

test_npm: test_npm_unit test_npm_node

demo_npm_browser: link_npm
	cd examples/wasm_browser && yarn install && yarn certificate && yarn start

install_deps_rust:
ifeq ($(SILENT),)
		@echo -n "Going to install the following cargo packages : \n- cargo-audit \n- cargo-license \n- cargo-outdated \n- cargo-watch \n- https \n- sccache \nDo you want to continue with the operation ? [y/N] " && read ans && [ $${ans:-N} = y ]
endif
	cargo install cargo-audit
	cargo install cargo-license
	cargo install cargo-outdated
	cargo install cargo-watch https
	cargo install sccache
	echo "Remember to add export RUSTC_WRAPPER=sccache to your environment."

deps: install_wasmpack install_deps_rust

checks:
	cargo fmt -- --check
	cargo clippy --all-features
	cargo audit

# prepreprocess circleci config so it can be ran locally
# Usage example:
# make ci JOB=test_service
ci:
	circleci config process .circleci/config.yml > .circleci/tmp.yml
	circleci build -c .circleci/tmp.yml --job ${JOB}

# Run this to have live refreshing of rust docs
docs_rust_edit:
	cargo watch -s 'cargo doc && browser-sync start --ss target/doc -s target/doc --directory --no-open'

tree:
	cargo tree --manifest-path signer/Cargo.toml > .tree_signer
	cargo tree --manifest-path signer-npm/Cargo.toml > .tree_signer_npm

fuzz_signer:
	cargo hfuzz run hfuzz-signer-zondax
