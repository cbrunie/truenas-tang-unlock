FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends clevis curl jq ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY unlock.sh /usr/local/bin/unlock
USER 65534
ENTRYPOINT ["unlock"]
