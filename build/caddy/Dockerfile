ARG VERSION

FROM caddy:${VERSION}-builder-alpine AS builder
ARG VERSION
USER root

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    xcaddy build v${VERSION} --output /caddy-bin \
        --with github.com/caddy-dns/cloudflare \
        --with github.com/abiosoft/caddy-hmac \
        --with github.com/lolPants/caddy-requestid \
        --with github.com/mholt/caddy-webdav \
        --with github.com/abiosoft/caddy-json-parse \
        --with github.com/porech/caddy-maxmind-geolocation \
        --with github.com/WeidiDeng/caddy-cloudflare-ip \
        --with github.com/fvbommel/caddy-combine-ip-ranges \
        --with github.com/mholt/caddy-l4 \
        --with github.com/caddyserver/transform-encoder \
        --with pkg.jsn.cam/caddy-defender \
        --with github.com/darkweak/souin/plugins/caddy \
        --with github.com/darkweak/storages/otter/caddy \
        --with github.com/lucaslorentz/caddy-docker-proxy@v2.10.0 \
        --with github.com/ewen-lbh/caddy-i18n@v0.1.2

RUN mkdir -p /data /config

FROM gcr.io/distroless/static-debian12:nonroot@sha256:2b7c93f6d6648c11f0e80a48558c8f77885eb0445213b8e69a6a0d7c89fc6ae4

ENV XDG_CONFIG_HOME=/config \
    XDG_DATA_HOME=/data

COPY --from=builder /caddy-bin /app/caddy
COPY --from=builder --chown=3000:3000 /data /data
COPY --from=builder --chown=3000:3000 /config /config


# COPY --chown=3000:3000 Caddyfile /etc/caddy/Caddyfile

USER 3000:3000
WORKDIR /config

#EXPOSE 80 443 443/udp 8443

ENTRYPOINT ["/app/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]