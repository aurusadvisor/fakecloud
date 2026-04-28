# Built and pushed on each fakecloud release tag by
# .github/workflows/docker-rds-images.yml as
#   ghcr.io/faiscadev/fakecloud-mariadb:<major>-<fakecloud-version>
# (plus a rolling :<major> tag). RdsRuntime::ensure_mariadb_image
# tries to pull that tag first and falls back to building from this
# Dockerfile locally when the pull fails.

# MARIADB_VERSION must sit before the first FROM so its substitution is
# available across all stages.
ARG MARIADB_VERSION=10.11

# Rebuild gosu from source with current Go to eliminate upstream
# mariadb image's bundled go1.24.6 stdlib CVEs in /usr/local/bin/gosu.
FROM golang:1.25-bookworm AS gosu-builder
ENV CGO_ENABLED=0
RUN go install -ldflags='-s -w' github.com/tianon/gosu@v0.0.0-20250923190938-6456aaa0f3c8

FROM mariadb:${MARIADB_VERSION}

USER root

COPY --from=gosu-builder /go/bin/gosu /usr/local/bin/gosu
RUN chmod 0755 /usr/local/bin/gosu
# UDF plugin API structs are vendored inline in fakecloud_udf.c so we
# only need a C compiler + libcurl headers. Keeping the dep set
# symmetric with the mysql Dockerfile means a single source of truth
# for the build rule.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc make libcurl4-openssl-dev libc6-dev ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY fakecloud_udf.c /tmp/fakecloud_udf.c
COPY fakecloud-bootstrap.sh /usr/local/bin/fakecloud-bootstrap.sh
COPY 99-fakecloud-bootstrap.sql.tmpl /tmp/99-fakecloud-bootstrap.sql.tmpl
RUN chmod +x /usr/local/bin/fakecloud-bootstrap.sh

# Compile the UDF and drop it into the server's plugin dir. Mariadb
# images use /usr/lib/mysql/plugin on Debian; probe a few common
# locations for forward compatibility.
RUN set -eux; \
    PLUGIN_DIR=""; \
    for d in /usr/lib/mysql/plugin /usr/lib/x86_64-linux-gnu/mariadb19/plugin /usr/lib/aarch64-linux-gnu/mariadb19/plugin /usr/lib64/mysql/plugin; do \
        if [ -d "$d" ]; then PLUGIN_DIR="$d"; break; fi; \
    done; \
    : "${PLUGIN_DIR:=/usr/lib/mysql/plugin}"; \
    mkdir -p "$PLUGIN_DIR"; \
    gcc -O2 -fPIC -shared -o "$PLUGIN_DIR/fakecloud_udf.so" \
        /tmp/fakecloud_udf.c -lcurl -lpthread; \
    rm /tmp/fakecloud_udf.c

ENTRYPOINT ["fakecloud-bootstrap.sh"]
CMD ["mariadbd"]
