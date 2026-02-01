FROM golang:1.25.6-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o receiver ./benchmark/cmd/receiver

FROM gcr.io/distroless/static-debian12
COPY --from=builder /app/receiver /receiver
ENTRYPOINT ["/receiver"]
CMD ["-port", "9090"]
