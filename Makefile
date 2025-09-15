.PHONY: all wasm server clean docker

# Build everything
all: clean wasm server docker

# Build WASM with standard Go (TinyGo has issues with js.FuncOf callbacks)
wasm:
	@echo "Building WASM module with standard Go..."
	GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o web/static/crypto.wasm cmd/wasm/main.go
	@echo "Copying Go's wasm_exec.js..."
	cp $$(go env GOROOT)/lib/wasm/wasm_exec.js web/static/wasm_exec.js
	@gzip -9 -k -f web/static/crypto.wasm
	@if command -v brotli >/dev/null 2>&1; then \
		brotli -9 -k -f web/static/crypto.wasm; \
	fi
	@echo "WASM build complete. Size: $$(ls -lh web/static/crypto.wasm | awk '{print $$5}')"

# Build server
server:
	@echo "Building server..."
	@go build -o secure_secret_share cmd/server/main.go
	@echo "Server build complete"

# Build Docker image
docker:
	docker build -t secure-secret-share .

# Clean build artifacts
clean:
	rm -f secure_secret_share
	rm -f web/static/crypto.wasm*
