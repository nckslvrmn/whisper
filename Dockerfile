FROM public.ecr.aws/docker/library/rust:1.96-alpine3.23 AS wasm-builder
RUN apk add --no-cache brotli binaryen && \
    rustup target add wasm32-unknown-unknown && \
    cargo install wasm-bindgen-cli --version 0.2.125 --locked
WORKDIR /src/wasm
COPY wasm/Cargo.toml wasm/Cargo.lock ./
RUN mkdir src && \
    printf 'pub fn warm_dependencies() {}\n' > src/lib.rs && \
    cargo build --release --target wasm32-unknown-unknown && \
    rm -rf src
COPY wasm/src ./src
RUN touch src/lib.rs && \
    cargo build --release --target wasm32-unknown-unknown && \
    wasm-bindgen --target web --force-enable-abort-handler --out-name crypto \
        --out-dir /wasm_out/ \
        target/wasm32-unknown-unknown/release/whisper_crypto.wasm && \
    wasm-opt --enable-exception-handling -Os /wasm_out/crypto_bg.wasm -o /wasm_out/crypto_bg.wasm && \
    gzip -9 -k -f /wasm_out/crypto_bg.wasm && \
    brotli -9 -k -f /wasm_out/crypto_bg.wasm

FROM public.ecr.aws/docker/library/golang:1.26-alpine3.23 AS go-builder
RUN apk add --no-cache ca-certificates musl-dev g++
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
COPY web ./web
COPY --from=wasm-builder /wasm_out/crypto.js ./web/static/crypto.js
COPY --from=wasm-builder /wasm_out/crypto_bg.wasm ./web/static/crypto_bg.wasm
COPY --from=wasm-builder /wasm_out/crypto_bg.wasm.gz ./web/static/crypto_bg.wasm.gz
COPY --from=wasm-builder /wasm_out/crypto_bg.wasm.br ./web/static/crypto_bg.wasm.br
RUN CGO_ENABLED=1 go build \
        -tags "osusergo,netgo,sqlite_omit_load_extension" \
        -trimpath \
        -ldflags='-linkmode external -extldflags "-static"' \
        -o whisper ./cmd/server/main.go
RUN mkdir -p /runtime/etc/ssl/certs /runtime/home/whisper /runtime/data /runtime/tmp && \
    cp /etc/ssl/certs/ca-certificates.crt /runtime/etc/ssl/certs/ca-certificates.crt && \
    printf 'whisper:x:1000:1000:Whisper:/home/whisper:/sbin/nologin\n' > /runtime/etc/passwd && \
    printf 'whisper:x:1000:\n' > /runtime/etc/group && \
    chown -R 1000:1000 /runtime/home/whisper /runtime/data /runtime/tmp && \
    chmod 1777 /runtime/tmp

FROM scratch
ARG VERSION=dev
ARG REVISION=unknown
ARG SOURCE=https://github.com/nckslvrmn/whisper
LABEL org.opencontainers.image.title="Whisper" \
      org.opencontainers.image.description="End-to-end encrypted secret sharing with WebAssembly-powered client-side encryption" \
      org.opencontainers.image.source="$SOURCE" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.licenses="MIT"
ENV HOME=/home/whisper
ENV TMPDIR=/tmp
COPY --from=go-builder /runtime/ /
COPY --from=go-builder /src/web /web/
COPY --from=go-builder --chmod=0755 /src/whisper /whisper
USER 1000:1000

EXPOSE 8081
ENTRYPOINT ["/whisper"]
