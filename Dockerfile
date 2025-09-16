FROM public.ecr.aws/docker/library/golang:alpine AS base
COPY . /src
WORKDIR /src
RUN apk add --no-cache ca-certificates brotli gzip && make

FROM alpine:latest AS app
COPY --from=base /src/web /web/
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=base --chmod=0755 /src/server /server

EXPOSE 8081
ENTRYPOINT ["/server"]
