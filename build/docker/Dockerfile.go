//go:build ignore

FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go build ./...

