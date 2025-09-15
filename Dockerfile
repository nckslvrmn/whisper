FROM public.ecr.aws/docker/library/golang:alpine AS base
RUN apk add --no-cache ca-certificates

# Build WASM module with TinyGo for smaller size
FROM tinygo/tinygo:latest AS wasm-build
# Install compression tools
RUN apt-get update && apt-get install -y brotli gzip && rm -rf /var/lib/apt/lists/*
COPY cmd/wasm /src/cmd/wasm
COPY pkg /src/pkg
COPY go.mod go.sum /src/
WORKDIR /src
# Build optimized WASM and create compressed versions
# Also copy TinyGo's wasm_exec.js for runtime support
RUN tinygo build -o crypto.wasm -target wasm -no-debug -opt=2 -panic=trap -scheduler=none -gc=leaking cmd/wasm/main.go && \
    cp $(tinygo env TINYGOROOT)/targets/wasm_exec.js wasm_exec.js && \
    gzip -9 -k crypto.wasm && \
    brotli -9 -k crypto.wasm

# Build server binary
FROM base AS server-build
COPY . /src
WORKDIR /src
RUN go mod download && go build -o server cmd/server/main.go

# Final application image
FROM alpine:latest AS app
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY web /web/
COPY --from=wasm-build /src/crypto.wasm /web/static/crypto.wasm
COPY --from=wasm-build /src/crypto.wasm.gz /web/static/crypto.wasm.gz
COPY --from=wasm-build /src/crypto.wasm.br /web/static/crypto.wasm.br
COPY --from=wasm-build /src/wasm_exec.js /web/static/wasm_exec.js
COPY --from=server-build --chmod=0755 /src/server /server

EXPOSE 8081
ENTRYPOINT ["/server"]
