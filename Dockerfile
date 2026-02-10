# Build stage
FROM golang:1.22-alpine AS builder
WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /myportal .

# Runtime stage
FROM alpine:3.19
RUN apk --no-cache add ca-certificates
WORKDIR /app

COPY --from=builder /myportal .
COPY templates/ ./templates/

EXPOSE 8080
ENV PORT=8080
USER nobody
ENTRYPOINT ["./myportal"]
