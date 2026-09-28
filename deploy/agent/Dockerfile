FROM node:22-bookworm-slim AS client
ARG CODEX_VERSION=0.155.0-alpha.16.3
RUN npm install --global "@openai/codex@${CODEX_VERSION}" && codex --version

FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libstdc++6 strace \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /bin/bash agent

COPY --from=client /usr/local/bin/node /usr/local/bin/node
COPY --from=client /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/@openai/codex/bin/codex.js /usr/local/bin/codex \
    && CODEX_NATIVE="$(find /usr/local/lib/node_modules/@openai -type f -path '*/codex/codex' | head -n 1)" \
    && test -n "${CODEX_NATIVE}" \
    && ln -s "${CODEX_NATIVE}" /usr/local/bin/codex-native \
    && codex --version \
    && codex-native --version

COPY deploy/frida/frida-gadget-17.18.0-linux-x86_64.so.xz /tmp/frida-gadget.so.xz
COPY deploy/frida/agent.js deploy/frida/libgadget.config /opt/transpect-frida/
RUN python3 -c "import hashlib, lzma, pathlib; xz=pathlib.Path('/tmp/frida-gadget.so.xz'); digest=hashlib.sha256(xz.read_bytes()).hexdigest(); assert digest=='3aa0f50e6948ccc0a1be5b14d5593a4596f3ce815bdbfb91d13c7123def45001', digest; data=lzma.decompress(xz.read_bytes()); assert hashlib.sha256(data).hexdigest()=='21594a4807fb00a598417c79c54f82eda32a0ebf74742702f4a0114dc0ebb295'; pathlib.Path('/opt/transpect-frida/libgadget.so').write_bytes(data)" \
    && chmod 0755 /opt/transpect-frida/libgadget.so \
    && chmod 0644 /opt/transpect-frida/agent.js /opt/transpect-frida/libgadget.config \
    && rm /tmp/frida-gadget.so.xz

WORKDIR /opt/transpect-trace
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir "aiohttp>=3.10,<4" "jsonschema>=4.23,<5" "pydantic>=2.8,<3" "typer>=0.12,<1" "zstandard>=0.23,<1"
COPY src ./src
RUN pip install --no-cache-dir --no-deps . \
    && mkdir -p /workspace /evidence \
    && chown -R agent:agent /workspace /evidence /home/agent

USER agent
WORKDIR /workspace
ENTRYPOINT ["ttrace-agent"]
