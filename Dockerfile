# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM node:26-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80 AS assets

WORKDIR /src
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund
COPY internal/web/static/app.js ./internal/web/static/app.js
RUN npm run build:assets

FROM scratch AS asset-output
COPY --from=assets /src/dist/app.js /app.js

FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY --from=assets /src/dist/app.js ./internal/web/static/app.js
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/openvasconf ./cmd/openvasconf \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/openvasconf-updater ./cmd/openvasconf-updater

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS updater

RUN apk add --no-cache \
        docker-cli=29.5.3-r0 \
        docker-cli-compose=5.1.4-r0 \
        libcrypto3=3.5.8-r0 \
        libssl3=3.5.8-r0 \
    && addgroup -g 1001 -S openvasconf \
    && adduser -u 1001 -S -D -H -G openvasconf openvasconf \
    && install -d -o openvasconf -g openvasconf -m 0700 /state /backups \
    && install -d -o openvasconf -g openvasconf -m 0750 /run/openvasconf-updater
COPY --from=build --chown=openvasconf:openvasconf /out/openvasconf-updater /usr/local/bin/openvasconf-updater

USER openvasconf:openvasconf
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["test", "-S", "/run/openvasconf-updater/updater.sock"]
ENTRYPOINT ["/usr/local/bin/openvasconf-updater"]

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS runtime

RUN apk add --no-cache \
        libcrypto3=3.5.8-r0 \
        libssl3=3.5.8-r0 \
    && addgroup -g 1001 -S openvasconf \
    && adduser -u 1001 -S -D -H -G openvasconf openvasconf \
    && install -d -o openvasconf -g openvasconf -m 0700 /data
COPY --from=build --chown=openvasconf:openvasconf /out/openvasconf /usr/local/bin/openvasconf

USER openvasconf:openvasconf
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/health/live"]
ENTRYPOINT ["/usr/local/bin/openvasconf"]
