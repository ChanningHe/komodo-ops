ARG KOMODO_VERSION
ARG TARGETPLATFORM
ARG TARGETARCH
ARG SOPS_VERSION=v3.11.0

FROM  --platform=$TARGETPLATFORM ghcr.io/moghtech/komodo-periphery:${KOMODO_VERSION} AS final
FROM  --platform=$TARGETPLATFORM ghcr.io/getsops/sops:${SOPS_VERSION} AS sops
#ARG ARCH=amd64

#ARG OP_VERSION=v2.32.0

FROM final
# Install age
RUN apt-get update \
    && apt-get install -y --no-install-recommends age

# Install sops
# RUN curl -Lo /usr/local/bin/sops "https://github.com/getsops/sops/releases/download/${SOPS_VERSION}/sops-${SOPS_VERSION}.linux.amd64" \
#     && chmod +x /usr/local/bin/sops 
COPY --from=sops /usr/local/bin/sops /usr/local/bin/sops

RUN sops --version \
    && mkdir -p /root/.config/sops/age

#RUN curl -Lo /usr/local/bin/sops \
#      "https://github.com/getsops/sops/releases/download/${SOPS_VERSION}/sops-${SOPS_VERSION}.linux.${TARGETARCH}" \
#    && chmod +x /usr/local/bin/sops
# Install 1Password op
# RUN curl -Lo op.zip "https://cache.agilebits.com/dist/1P/op2/pkg/${OP_VERSION}/op_linux_${ARCH}_${OP_VERSION}.zip"\
#    && unzip -d op op.zip \
#    && rm op.zip \
#    && mv op/op /usr/local/bin/op \
#    && rm -rf op \
#    && chmod +x /usr/local/bin/op

#RUN apt-get autoremove -y unzip \
#    && apt-get clean \
#    && rm -rf /var/lib/apt/lists/*

# Create the sops directory
#RUN mkdir -p $HOME/.config/sops/age
