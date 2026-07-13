FROM golang:1.25-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o push-gateway ./cmd/server

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/push-gateway /usr/local/bin/
RUN addgroup -S push-gateway && \
    adduser -S -G push-gateway -h /var/lib/push-gateway push-gateway && \
    mkdir -p /data && \
    chown push-gateway:push-gateway /data
VOLUME /data
EXPOSE 8080
ENV SQLITE_PATH=/data/push-gateway.db
USER push-gateway
CMD ["push-gateway"]
