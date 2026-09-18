module resolve-probe

// Match the toolchain Jenkins builds taskrouter with (build/ci/Dockerfile.jenkins
// is FROM golang:1.19). The TLS ClientHello changed across later releases, so a
// result from a different toolchain is not comparable to staging.
go 1.19
