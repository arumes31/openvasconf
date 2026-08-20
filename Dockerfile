# syntax=docker/dockerfile:1.7
FROM node:26-alpine AS assets

WORKDIR /src
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund
COPY internal/web/static/app.js ./internal/web/static/app.js
RUN npm run build:assets

FROM scratch AS asset-output
COPY --from=assets /src/dist/app.js /app.js

FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY --from=assets /src/dist/app.js ./internal/web/static/app.js
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/openvasconf ./cmd/openvasconf

FROM alpine:3.24

RUN addgroup -g 1001 -S openvasconf \
    && adduser -u 1001 -S -D -H -G openvasconf openvasconf \
    && install -d -o openvasconf -g openvasconf -m 0700 /data
COPY --from=build --chown=openvasconf:openvasconf /out/openvasconf /usr/local/bin/openvasconf

USER openvasconf:openvasconf
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/health/live || exit 1
ENTRYPOINT ["/usr/local/bin/openvasconf"]
