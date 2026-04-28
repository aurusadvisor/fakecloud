# Built and pushed on each fakecloud release tag by
# .github/workflows/docker-rds-images.yml as
#   ghcr.io/faiscadev/fakecloud-mariadb:<major>-<fakecloud-version>
# (plus a rolling :<major> tag). RdsRuntime::ensure_mariadb_image
# tries to pull that tag first and falls back to building from this
# Dockerfile locally when the pull fails.

ARG MARIADB_VERSION=10.11
FROM mariadb:${MARIADB_VERSION}

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc make libcurl4-openssl-dev libmariadb-dev libc6-dev ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY fakecloud_udf.c /tmp/fakecloud_udf.c
COPY fakecloud-bootstrap.sh /usr/local/bin/fakecloud-bootstrap.sh
COPY 99-fakecloud-bootstrap.sql.tmpl /tmp/99-fakecloud-bootstrap.sql.tmpl
RUN chmod +x /usr/local/bin/fakecloud-bootstrap.sh

# MariaDB ships mysql_config-style headers via libmariadb-dev. The
# plugin dir lives at /usr/lib/mysql/plugin (or under the mariadb
# tree on some images); honor whatever mysql_config reports first.
RUN PLUGIN_DIR="$(mariadb_config --plugindir 2>/dev/null \
        || mysql_config --plugindir 2>/dev/null \
        || echo /usr/lib/mysql/plugin)" \
    && mkdir -p "$PLUGIN_DIR" \
    && CFLAGS="$(mariadb_config --cflags 2>/dev/null \
        || mysql_config --cflags 2>/dev/null \
        || echo -I/usr/include/mariadb)" \
    && gcc -O2 -fPIC -shared $CFLAGS -o "$PLUGIN_DIR/fakecloud_udf.so" \
        /tmp/fakecloud_udf.c -lcurl -lpthread \
    && rm /tmp/fakecloud_udf.c

ENTRYPOINT ["fakecloud-bootstrap.sh"]
CMD ["mariadbd"]
