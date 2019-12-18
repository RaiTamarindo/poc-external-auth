FROM golang:1.13.5-alpine3.10 as builder

ENV CGO_ENABLED=0

RUN apk add --no-cache git

WORKDIR /app

COPY . .
RUN go mod download
RUN go build -o /app/api -mod=readonly ./main.go

FROM alpine as release

RUN apk add --no-cache ca-certificates
COPY --from=builder /app/api /api

ENTRYPOINT [ "/api" ]