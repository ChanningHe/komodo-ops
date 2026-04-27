ARG VERSION
FROM caddy:${VERSION}-builder-alpine AS builder
ARG VERSION
ARG TARGETARCH
ARG VENDOR
#ARG XCADDY_VERSION=0.4.5

USER root
WORKDIR /app

RUN xcaddy build v${VERSION} --output /caddy-bin \
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
    --with github.com/hslatman/caddy-crowdsec-bouncer/http@main \
    --with github.com/hslatman/caddy-crowdsec-bouncer/layer4@main \
    --with pkg.jsn.cam/caddy-defender \
    --with github.com/darkweak/souin/plugins/caddy \
    --with github.com/darkweak/storages/otter/caddy \
    --with github.com/lucaslorentz/caddy-docker-proxy@v2.10.0 \
    --with github.com/ewen-lbh/caddy-i18n@v0.1.2 && \
    chmod 755 "/caddy-bin"

FROM gcr.io/distroless/static-debian12:nonroot@sha256:2b7c93f6d6648c11f0e80a48558c8f77885eb0445213b8e69a6a0d7c89fc6ae4

USER 568:568

COPY --from=builder /caddy-bin "/app/caddy"
COPY . /

EXPOSE 8080 8443
WORKDIR /config

CMD ["/app/caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]