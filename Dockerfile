# Mirrors taskrouter build/ci/Dockerfile.jenkins so this probe is built by the
# same toolchain and runs on the same base image as the service it imitates.
# Identical Go version means an identical TLS ClientHello; identical alpine +
# ca-certificates means an identical trust store.
FROM golang:1.19 as builder

WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /probe .

FROM alpine:3.14
RUN apk update && apk add ca-certificates && update-ca-certificates
COPY --from=builder /probe /probe
ENTRYPOINT ["/probe"]
