FROM golang:1.26.5-alpine3.23 AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy source
COPY *.go ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o speedtest .

# Final image
FROM alpine:3.23.3

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /app/speedtest .

EXPOSE 9876

RUN adduser -D -H -s /sbin/nologin appuser
USER appuser

CMD ["./speedtest"]
