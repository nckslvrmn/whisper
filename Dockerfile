FROM public.ecr.aws/docker/library/rust:alpine AS wasm-builder
RUN apk add --no-cache brotli binaryen && \
    rustup target add wasm32-unknown-unknown && \
    cargo install wasm-bindgen-cli --version 0.2.113 --locked
WORKDIR /src
COPY wasm/ ./wasm/
RUN cd wasm && cargo build --release --target wasm32-unknown-unknown && \
    wasm-bindgen --target web --out-name crypto \
        --out-dir /wasm_out/ \
        target/wasm32-unknown-unknown/release/whisper_crypto.wasm && \
    wasm-opt -Os /wasm_out/crypto_bg.wasm -o /wasm_out/crypto_bg.wasm && \
    gzip -9 -k -f /wasm_out/crypto_bg.wasm && \
    brotli -9 -k -f /wasm_out/crypto_bg.wasm

FROM public.ecr.aws/docker/library/golang:alpine AS go-builder
RUN apk add --no-cache musl-dev g++
WORKDIR /src
COPY . .
COPY --from=wasm-builder /wasm_out/crypto.js ./web/static/crypto.js
COPY --from=wasm-builder /wasm_out/crypto_bg.wasm ./web/static/crypto_bg.wasm
COPY --from=wasm-builder /wasm_out/crypto_bg.wasm.gz ./web/static/crypto_bg.wasm.gz
COPY --from=wasm-builder /wasm_out/crypto_bg.wasm.br ./web/static/crypto_bg.wasm.br
RUN go mod download && \
    CGO_ENABLED=1 go build -o whisper ./cmd/server/main.go

FROM public.ecr.aws/docker/library/alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=go-builder /src/web /web/
COPY --from=go-builder --chmod=0755 /src/whisper /whisper

EXPOSE 8081
ENTRYPOINT ["/whisper"]
