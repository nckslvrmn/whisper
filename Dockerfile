FROM public.ecr.aws/docker/library/golang:alpine AS base
COPY . /src
WORKDIR /src
ENV PATH="/root/.cargo/bin:${PATH}"
RUN apk add --no-cache brotli gzip make g++ curl musl-dev && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path && \
    rustup target add wasm32-unknown-unknown && \
    cargo install wasm-pack && \
    make

FROM public.ecr.aws/docker/library/alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=base /src/web /web/
COPY --from=base --chmod=0755 /src/whisper /whisper

EXPOSE 8081
ENTRYPOINT ["/whisper"]
