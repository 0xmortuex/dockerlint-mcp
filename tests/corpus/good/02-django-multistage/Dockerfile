# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install -r requirements.txt

FROM python:3.12-slim AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home django

WORKDIR /srv/app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=django:django . .

USER django
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD ["python", "manage.py", "check"]
ENTRYPOINT ["gunicorn"]
CMD ["config.wsgi:application", "--bind", "0.0.0.0:8000"]
