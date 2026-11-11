# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM node:26.12.1-alpine3.24@sha256:40cd011b55415bc894e45b02fdd5a5dfde056921b7d23a64c74f80497af48797 AS assets

WORKDIR /src
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund
COPY internal/web/static/app.js ./internal/web/static/app.js
RUN npm run build:assets

FROM scratch AS asset-output
COPY --from=assets /src/dist/app.js /app.js

FROM golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY --from=assets /src/dist/app.js ./internal/web/static/app.js
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/openvasconf ./cmd/openvasconf \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/openvasconf-updater ./cmd/openvasconf-updater

FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS updater

RUN apk add --no-cache \
        docker-cli=29.9.3-r1 \
        docker-cli-compose=5.6.1-r0 \
        libcrypto3=3.5.9-r0 \
        libssl3=3.5.9-r0 \
    && addgroup -g 1001 -S openvasconf \
    && adduser -u 1001 -S -D -H -G openvasconf openvasconf \
    && install -d -o openvasconf -g openvasconf -m 0700 /state /backups \
    && install -d -o openvasconf -g openvasconf -m 0750 /run/openvasconf-updater
COPY --from=build --chown=openvasconf:openvasconf /out/openvasconf-updater /usr/local/bin/openvasconf-updater

USER 1001:1001
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["test", "-S", "/run/openvasconf-updater/updater.sock"]
ENTRYPOINT ["/usr/local/bin/openvasconf-updater"]

FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS runtime

RUN apk add --no-cache \
        libcrypto3=3.5.9-r0 \
        libssl3=3.5.9-r0 \
    && addgroup -g 1001 -S openvasconf \
    && adduser -u 1001 -S -D -H -G openvasconf openvasconf \
    && install -d -o openvasconf -g openvasconf -m 0700 /data
COPY --from=build --chown=openvasconf:openvasconf /out/openvasconf /usr/local/bin/openvasconf

USER 1001:1001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/health/live"]
ENTRYPOINT ["/usr/local/bin/openvasconf"]
