FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan \
    strongswan-charon \
    strongswan-swanctl \
    libstrongswan-standard-plugins \
    libcharon-extra-plugins \
    curl \
    iproute2 \
    iputils-ping \
    dnsutils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy strongSwan client config
COPY swanctl.conf /etc/swanctl/conf.d/prototype.conf

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
