FROM python:3.11-slim

LABEL maintainer="GateKeeper Team <security@gatekeeper.local>"
LABEL version="1.0.4"
LABEL description="GateKeeper - AI安全网络防御系统"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev libcap2-bin iptables libnet1 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash gkuser
WORKDIR /opt/gatekeeper
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chown -R gkuser:gkuser /opt/gatekeeper
RUN mkdir -p data logs models uploads backups data/certs && \
    chown -R gkuser:gkuser /opt/gatekeeper/data /opt/gatekeeper/logs /opt/gatekeeper/models /opt/gatekeeper/uploads /opt/gatekeeper/backups /opt/gatekeeper/data/certs
EXPOSE 8443 8080
HEALTHCHECK --start-period=30s --interval=30s --timeout=5s --retries=3 CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"]
ENV GK_WEB_PORT=8080 GK_WEB_SSL_ENABLED=false GK_DB_DRIVER=sqlite
USER gkuser
CMD ["python3", "-m", "core.app"]
