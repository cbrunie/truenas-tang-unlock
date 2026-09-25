FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends clevis python3 python3-websocket ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY unlock.py /usr/local/bin/unlock
USER 65534
ENTRYPOINT ["python3", "/usr/local/bin/unlock"]
