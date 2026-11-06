# Pinned multi-architecture manifest for python:3.12.16-slim-bookworm.
FROM python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --gid 10001 notevault \
    && useradd --uid 10001 --gid notevault --no-create-home --shell /usr/sbin/nologin notevault \
    && mkdir -p /app /data \
    && chown -R notevault:notevault /app /data

WORKDIR /app
COPY --chown=notevault:notevault requirements.lock ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock
COPY --chown=notevault:notevault app.py ./

USER 10001:10001
EXPOSE 8080
CMD ["gunicorn", "--bind=0.0.0.0:8080", "--workers=1", "--threads=4", "--timeout=30", "--worker-tmp-dir=/tmp", "--no-control-socket", "--access-logfile=-", "--error-logfile=-", "app:create_app()"]
