# Built and pushed on each fakecloud release tag by
# .github/workflows/docker-rds-images.yml as
#   ghcr.io/faiscadev/fakecloud-postgres:<major>-<fakecloud-version>
# (plus a rolling :<major> tag). RdsRuntime::ensure_postgres_image
# tries to pull that tag first and falls back to building from this
# Dockerfile locally when the pull fails (dev / unreleased / airgapped).
ARG PG_VERSION=16
FROM postgres:${PG_VERSION}
ARG PG_VERSION

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        postgresql-plpython3-${PG_VERSION} \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY aws_commons.control aws_commons--1.0.sql \
     aws_lambda.control aws_lambda--1.0.sql \
     /usr/share/postgresql/${PG_VERSION}/extension/
