FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    tcpdump \
    python3 \
    python3-pip \
    ca-certificates \
    tzdata \
 && pip3 install --no-cache-dir watchdog requests urllib3 --break-system-packages \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY feeder.py /app/feeder.py

RUN mkdir -p /pcaps && chmod 777 /pcaps

ENTRYPOINT ["python3", "/app/feeder.py"]

CMD ["--iface game --outdir /pcaps --caronte http://localhost:3333/api/pcap/upload -U admin -P admin --rotate 3 --remove-after"]
