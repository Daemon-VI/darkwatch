# Darkwatch as a container image: the CLI with Tor already inside, for running scans anywhere.
#
#   docker run --rm ghcr.io/daemon-vi/darkwatch --help
#   docker run --rm -v "$PWD/dw:/work" ghcr.io/daemon-vi/darkwatch setup --name "Acme Inc" --company
#   docker run --rm -v "$PWD/dw:/work" ghcr.io/daemon-vi/darkwatch run
#
# The image is for the read-only scan/CLI. The dashboard (`darkwatch web`) binds to loopback by
# design and is meant to run on your own machine, not exposed from a container.

FROM python:3.12-slim AS build
WORKDIR /src
RUN pip install --no-cache-dir build
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m build --wheel --outdir /dist

FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/Daemon-VI/darkwatch"
LABEL org.opencontainers.image.description="Darkwatch — read-only dark web exposure monitor (CLI, with Tor)"
LABEL org.opencontainers.image.licenses="MIT"
# tor: the onion sources fetch over it; darkwatch finds `tor` on PATH and manages it per run
RUN apt-get update \
    && apt-get install -y --no-install-recommends tor ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl
RUN useradd -m -u 10001 watcher
USER watcher
WORKDIR /work
ENTRYPOINT ["darkwatch"]
CMD ["--help"]
