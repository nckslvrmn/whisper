FROM public.ecr.aws/docker/library/golang:alpine AS base
RUN apk add --no-cache ca-certificates

FROM base AS build
COPY . /src
WORKDIR /src
RUN go mod download && go build main.go

FROM alpine:latest AS app
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY views /views/
COPY static /static/
COPY --from=build --chmod=0755 /src/main /main
ENTRYPOINT ["/main"]