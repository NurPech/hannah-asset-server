FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS builder
WORKDIR /build
COPY app/go.mod app/go.sum ./
RUN go mod download
COPY app/*.go app/*.html ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o server .

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/server /server
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/server"]
