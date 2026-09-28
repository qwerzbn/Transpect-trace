FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates strace \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/transpect-trace
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir "aiohttp>=3.10,<4" "jsonschema>=4.23,<5" "pydantic>=2.8,<3" "typer>=0.12,<1" "zstandard>=0.23,<1"
COPY src ./src
RUN pip install --no-cache-dir --no-deps .

EXPOSE 9000
HEALTHCHECK --interval=2s --timeout=2s --retries=30 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9000/health', timeout=1)"]
ENTRYPOINT ["strace", "-ff", "-ttt", "-yy", "-s", "1024", "-e", "trace=%process,%file,socket,connect,bind,listen,accept,accept4,close,dup,dup2,pipe,pipe2", "-o", "/evidence/raw/system/gateway-strace", "ttrace-gateway"]
