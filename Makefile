.PHONY: all clean deps wasm server clean

all: clean wasm deps server

deps:
	@go mod download

wasm:
	@echo "Building WASM module with Rust/wasm-pack..."
	cd wasm && PATH="$(HOME)/.cargo/bin:$(PATH)" wasm-pack build --target web --out-name crypto --out-dir ../wasm_pkg
	cp wasm_pkg/crypto.js web/static/crypto.js
	cp wasm_pkg/crypto_bg.wasm web/static/crypto_bg.wasm
	rm -rf wasm_pkg
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
	rm -rf wasm_pkg
