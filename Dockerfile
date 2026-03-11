FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN go build -o firewall ./cmd/main.go

FROM alpine:latest
RUN apk add --no-cache iptables ip6tables bash curl
COPY --from=builder /app/firewall /usr/local/bin/
COPY --from=builder /app/static /static
EXPOSE 8080 5354/udp
CMD ["/usr/local/bin/firewall"]