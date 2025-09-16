FROM public.ecr.aws/docker/library/golang:alpine AS base
COPY . /src
WORKDIR /src
RUN apk add --no-cache brotli gzip make && make

FROM public.ecr.aws/docker/library/alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=base /src/web /web/
COPY --from=base --chmod=0755 /src/secure_secret_share /secure_secret_share

EXPOSE 8081
ENTRYPOINT ["/secure_secret_share"]
