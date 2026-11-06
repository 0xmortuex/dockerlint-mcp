# syntax=docker/dockerfile:1.7
ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-slim AS base

ARG APP_UID=10001
ENV PYTHONUNBUFFERED=1

RUN <<EOF
set -eux
apt-get update
apt-get install -y --no-install-recommends tini
rm -rf /var/lib/apt/lists/*
useradd --system --uid "${APP_UID}" app
EOF

WORKDIR /app
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt

COPY --chown=app:app . .
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD ["python", "-m", "app.healthcheck"]
ENTRYPOINT ["tini", "--"]
CMD ["python", "-m", "app"]
