FROM node:22-bookworm-slim AS client
ARG CLAUDE_VERSION=1.0.128
RUN npm install --global "@anthropic-ai/claude-code@${CLAUDE_VERSION}" && claude --version

FROM python:3.12-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:0.12.18 /uv /usr/local/bin/uv
ENV PATH="/opt/transpect-trace/.venv/bin:$PATH" UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libstdc++6 strace \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /bin/bash agent

COPY --from=client /usr/local/bin/node /usr/local/bin/node
COPY --from=client /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/@anthropic-ai/claude-code/cli.js /usr/local/bin/claude \
    && claude --version

COPY deploy/frida/frida-gadget-17.18.0-linux-x86_64.so.xz /tmp/frida-gadget.so.xz
COPY deploy/frida/agent.js deploy/frida/libgadget.config /opt/transpect-frida/
RUN python3 -c "import hashlib, lzma, pathlib; xz=pathlib.Path('/tmp/frida-gadget.so.xz'); digest=hashlib.sha256(xz.read_bytes()).hexdigest(); assert digest=='3aa0f50e6948ccc0a1be5b14d5593a4596f3ce815bdbfb91d13c7123def45001', digest; data=lzma.decompress(xz.read_bytes()); assert hashlib.sha256(data).hexdigest()=='21594a4807fb00a598417c79c54f82eda32a0ebf74742702f4a0114dc0ebb295'; pathlib.Path('/opt/transpect-frida/libgadget.so').write_bytes(data)" \
    && chmod 0755 /opt/transpect-frida/libgadget.so \
    && chmod 0644 /opt/transpect-frida/agent.js /opt/transpect-frida/libgadget.config \
    && rm /tmp/frida-gadget.so.xz

WORKDIR /opt/transpect-trace
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project --no-cache
COPY src ./src
RUN uv sync --locked --no-dev --no-editable --no-cache \
    && mkdir -p /workspace /evidence \
    && chown -R agent:agent /workspace /evidence /home/agent

USER agent
WORKDIR /workspace
ENTRYPOINT ["python3", "-m", "transpect_trace.clients.claude_entrypoint"]
