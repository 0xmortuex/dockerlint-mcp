FROM ubuntu:24.04

ARG TOOL_VERSION=1.8.2
ARG TOOL_SHA256=0f1c2b0d9e3a4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSLo /tmp/tool.tgz "https://example.com/tool/${TOOL_VERSION}/tool.tgz" \
    && echo "${TOOL_SHA256}  /tmp/tool.tgz" | sha256sum -c - \
    && tar -xzf /tmp/tool.tgz -C /usr/local/bin \
    && rm /tmp/tool.tgz

RUN useradd --system --uid 10001 --create-home runner
USER runner
WORKDIR /home/runner
VOLUME ["/home/runner/data"]
EXPOSE 7000/tcp
HEALTHCHECK --interval=1m --timeout=5s CMD tool status
ENTRYPOINT ["/usr/bin/tini", "--", "tool"]
CMD ["serve"]
