# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM node:26-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019 AS assets

WORKDIR /src
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund
COPY internal/web/static/app.js ./internal/web/static/app.js
RUN npm run build:assets

FROM scratch AS asset-output
COPY --from=assets /src/dist/app.js /app.js

FROM golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY --from=assets /src/dist/app.js ./internal/web/static/app.js
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/openvasconf ./cmd/openvasconf \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/openvasconf-updater ./cmd/openvasconf-updater

FROM docker:29-cli@sha256:000bb62ff495f986c9f5578eb67cc2cb98b91138eda81d7762d5371eb8a497fe AS updater

RUN addgroup -g 1001 -S openvasconf \
    && adduser -u 1001 -S -D -H -G openvasconf openvasconf \
    && install -d -o openvasconf -g openvasconf -m 0700 /state /backups \
    && install -d -o openvasconf -g openvasconf -m 0750 /run/openvasconf-updater
COPY --from=build --chown=openvasconf:openvasconf /out/openvasconf-updater /usr/local/bin/openvasconf-updater

USER openvasconf:openvasconf
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["test", "-S", "/run/openvasconf-updater/updater.sock"]
ENTRYPOINT ["/usr/local/bin/openvasconf-updater"]

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS runtime

RUN addgroup -g 1001 -S openvasconf \
    && adduser -u 1001 -S -D -H -G openvasconf openvasconf \
    && install -d -o openvasconf -g openvasconf -m 0700 /data
COPY --from=build --chown=openvasconf:openvasconf /out/openvasconf /usr/local/bin/openvasconf

USER openvasconf:openvasconf
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/health/live"]
ENTRYPOINT ["/usr/local/bin/openvasconf"]
