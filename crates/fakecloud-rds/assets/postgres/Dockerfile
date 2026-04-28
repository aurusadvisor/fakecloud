# Built and pushed on each fakecloud release tag by
# .github/workflows/docker-rds-images.yml as
#   ghcr.io/faiscadev/fakecloud-postgres:<major>-<fakecloud-version>
# (plus a rolling :<major> tag). RdsRuntime::ensure_postgres_image
# tries to pull that tag first and falls back to building from this
# Dockerfile locally when the pull fails (dev / unreleased / airgapped).
# PG_VERSION must sit before the first FROM so its substitution is
# available across all stages. Inside each stage it has to be
# re-declared (Dockerfile spec) for `RUN`/`COPY` references to expand.
ARG PG_VERSION=16

# Rebuild `gosu` from source with current Go to eliminate the upstream
# postgres image's bundled `/usr/local/bin/gosu` Go-stdlib CVEs (Trivy
# flags 8 HIGH + 1 CRITICAL on go1.24.6 stdlib at scan time). gosu
# upstream is rarely re-released; pinning the source version + rebuilding
# on every image build means we control the stdlib version baked in.
FROM golang:1.25-bookworm AS gosu-builder
ENV CGO_ENABLED=0
RUN go install -ldflags='-s -w' github.com/tianon/gosu@v1.17

FROM postgres:${PG_VERSION}
ARG PG_VERSION

COPY --from=gosu-builder /go/bin/gosu /usr/local/bin/gosu
RUN chmod 0755 /usr/local/bin/gosu

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        postgresql-plpython3-${PG_VERSION} \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY aws_commons.control aws_commons--1.1.sql aws_commons--1.0--1.1.sql \
     aws_lambda.control aws_lambda--1.0.sql \
     aws_s3.control aws_s3--1.0.sql \
     /usr/share/postgresql/${PG_VERSION}/extension/
