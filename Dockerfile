FROM public.ecr.aws/docker/library/golang:alpine AS base
RUN apk add --no-cache ca-certificates brotli gzip
COPY . /src
WORKDIR /src

RUN go mod download && go build -o server cmd/server/main.go && \
    GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o web/static/crypto.wasm cmd/wasm/main.go && \
    cp $(go env GOROOT)/lib/wasm/wasm_exec.js web/static/wasm_exec.js && \
    gzip -9 -k web/static/crypto.wasm && \
    brotli -9 -k web/static/crypto.wasm

FROM alpine:latest AS app
COPY --from=base /src/web /web/
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=base --chmod=0755 /src/server /server

EXPOSE 8081
ENTRYPOINT ["/server"]
