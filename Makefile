.PHONY: all clean deps wasm server clean

all: clean wasm deps server

deps:
	@go mod download

wasm:
	@echo "Building WASM module..."
	cd wasm && cargo build --release --target wasm32-unknown-unknown
	PATH="$(HOME)/.cargo/bin:$(PATH)" wasm-bindgen --target web --out-name crypto \
		--out-dir web/static/ \
		wasm/target/wasm32-unknown-unknown/release/whisper_crypto.wasm
	@if command -v wasm-opt >/dev/null 2>&1; then \
		wasm-opt -Os web/static/crypto_bg.wasm -o web/static/crypto_bg.wasm; \
	fi
	@gzip -9 -k -f web/static/crypto_bg.wasm
	@if command -v brotli >/dev/null 2>&1; then \
		brotli -9 -k -f web/static/crypto_bg.wasm; \
	fi
	@echo "WASM build complete. Size: $$(ls -lh web/static/crypto_bg.wasm | awk '{print $$5}')"

server: deps
	@echo "Building server..."
	@CGO_ENABLED=1 go build -o whisper cmd/server/main.go
	@echo "Server build complete"

clean:
	rm -f whisper
	rm -f web/static/crypto_bg.wasm*
	rm -f web/static/crypto.js
	rm -f web/static/wasm_exec.js
	rm -f web/static/*.br
	rm -f web/static/*.gz
