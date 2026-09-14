FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/antserver ./cmd/antserver

FROM alpine:latest
RUN apk add --no-cache iptables iproute2 bash curl

COPY --from=builder /bin/antserver /usr/local/bin/antserver

EXPOSE 51820/udp 8443/tcp

ENTRYPOINT ["/usr/local/bin/antserver", "-udp", ":51820", "-tls", ":8443", "-nat=true"]
