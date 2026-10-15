FROM python:3.12-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:0.12.18 /uv /usr/local/bin/uv
ENV PATH="/opt/transpect-trace/.venv/bin:$PATH" UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates strace \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/transpect-trace
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project --no-cache
COPY src ./src
RUN uv sync --locked --no-dev --no-editable --no-cache

EXPOSE 9000
HEALTHCHECK --interval=2s --timeout=2s --retries=30 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9000/health', timeout=1)"]
ENTRYPOINT ["strace", "-ff", "-ttt", "-yy", "-s", "1024", "-e", "trace=%process,%file,socket,connect,bind,listen,accept,accept4,close,dup,dup2,pipe,pipe2", "-o", "/evidence/raw/system/gateway-strace", "ttrace-gateway"]
