.PHONY: all clean deps wasm server clean

all: clean deps wasm server

deps:
	@go mod download

wasm: deps
	@echo "Building WASM module with standard Go..."
	GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o web/static/crypto.wasm cmd/wasm/main.go
	@echo "Copying Go's wasm_exec.js..."
	cp $$(go env GOROOT)/lib/wasm/wasm_exec.js web/static/wasm_exec.js
	@gzip -9 -k -f web/static/crypto.wasm
	@if command -v brotli >/dev/null 2>&1; then \
		brotli -9 -k -f web/static/crypto.wasm; \
	fi
	@echo "WASM build complete. Size: $$(ls -lh web/static/crypto.wasm | awk '{print $$5}')"

server:
	@echo "Building server..."
	@CGO_ENABLED=1 go build -o whisper cmd/server/main.go
	@echo "Server build complete"

clean:
	rm -f whisper
	rm -f web/static/crypto.wasm*
	rm -f web/static/wasm_exec.js
