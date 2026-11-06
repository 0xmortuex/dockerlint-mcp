FROM alpine:3.20

LABEL org.opencontainers.image.source="https://example.com/repo" \
      org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache ca-certificates jq tini \
    && adduser -S -u 10001 tool

COPY --chown=tool entrypoint.sh /usr/local/bin/entrypoint.sh

USER tool
WORKDIR /home/tool
HEALTHCHECK NONE
STOPSIGNAL SIGTERM
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["--help"]
