# Built and pushed on each fakecloud release tag by
# .github/workflows/docker-rds-images.yml as
#   ghcr.io/faiscadev/fakecloud-mysql:<major>-<fakecloud-version>
# (plus a rolling :<major> tag). RdsRuntime::ensure_mysql_image tries
# to pull that tag first and falls back to building from this Dockerfile
# locally when the pull fails.
#
# Bakes a small libcurl-backed UDF (`fakecloud_post`, `fakecloud_post_async`)
# plus Aurora-compatible `mysql.lambda_sync`/`mysql.lambda_async` stored
# procedures so SQL inside an RDS-managed MySQL instance can invoke
# fakecloud Lambda functions.

ARG MYSQL_VERSION=8.0
FROM mysql:${MYSQL_VERSION}

USER root
# UDF needs only gcc + libcurl headers; mysql plugin API structs are
# vendored inline in fakecloud_udf.c (the upstream mysql:8.0 image
# strips its community release repo so `mysql-community-devel` is not
# installable, and adding it back hard-codes a brittle URL).
RUN set -eux; \
    if command -v microdnf >/dev/null 2>&1; then \
        microdnf install -y \
            gcc make libcurl-devel glibc-devel; \
        microdnf clean all; \
    elif command -v apt-get >/dev/null 2>&1; then \
        apt-get update; \
        apt-get install -y --no-install-recommends \
            gcc make libcurl4-openssl-dev libc6-dev ca-certificates; \
        rm -rf /var/lib/apt/lists/*; \
    else \
        echo "no supported package manager found in base image" >&2; \
        exit 1; \
    fi

# UDF source + bootstrap SQL.
COPY fakecloud_udf.c /tmp/fakecloud_udf.c
COPY fakecloud-bootstrap.sh /usr/local/bin/fakecloud-bootstrap.sh
COPY 99-fakecloud-bootstrap.sql.tmpl /tmp/99-fakecloud-bootstrap.sql.tmpl
RUN chmod +x /usr/local/bin/fakecloud-bootstrap.sh

# Compile the UDF and drop it into the server's plugin dir. We probe
# common locations because Oracle Linux ships /usr/lib64/mysql/plugin
# while Debian-based mysql images use /usr/lib/mysql/plugin.
RUN set -eux; \
    PLUGIN_DIR=""; \
    for d in /usr/lib64/mysql/plugin /usr/lib/mysql/plugin /usr/lib/x86_64-linux-gnu/mysql/plugin; do \
        if [ -d "$d" ]; then PLUGIN_DIR="$d"; break; fi; \
    done; \
    : "${PLUGIN_DIR:=/usr/lib/mysql/plugin}"; \
    mkdir -p "$PLUGIN_DIR"; \
    gcc -O2 -fPIC -shared -o "$PLUGIN_DIR/fakecloud_udf.so" \
        /tmp/fakecloud_udf.c -lcurl -lpthread; \
    rm /tmp/fakecloud_udf.c

# The bootstrap shell script substitutes FAKECLOUD_* env vars into the
# template SQL and drops the result into /docker-entrypoint-initdb.d/
# so the official mysql entrypoint picks it up on first start.
ENTRYPOINT ["fakecloud-bootstrap.sh"]
CMD ["mysqld"]
