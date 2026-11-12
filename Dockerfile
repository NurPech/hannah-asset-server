FROM golang:1.27-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS builder
WORKDIR /build
COPY app/go.mod app/go.sum ./
RUN go mod download
COPY app/*.go app/*.html ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o server .
RUN mkdir /data && chown 1000:1000 /data

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/server /server
# New named volumes inherit this ownership. Existing (root-owned) volumes are
# migrated by the server itself on start: it chowns STORAGE_PATH to 1000:1000
# and drops privileges (see app/privileges_linux.go). The image intentionally has
# no USER yet, otherwise the migration could not run; a later release will add it.
COPY --from=builder --chown=1000:1000 /data /data
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/server"]
