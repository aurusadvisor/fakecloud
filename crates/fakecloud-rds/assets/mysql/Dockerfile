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
RUN microdnf install -y \
        gcc \
        make \
        libcurl-devel \
        glibc-devel \
    || ( apt-get update \
         && apt-get install -y --no-install-recommends \
            gcc make libcurl4-openssl-dev libc6-dev ca-certificates curl \
         && rm -rf /var/lib/apt/lists/* )

# UDF source + bootstrap SQL.
COPY fakecloud_udf.c /tmp/fakecloud_udf.c
COPY fakecloud-bootstrap.sh /usr/local/bin/fakecloud-bootstrap.sh
COPY 99-fakecloud-bootstrap.sql.tmpl /tmp/99-fakecloud-bootstrap.sql.tmpl
RUN chmod +x /usr/local/bin/fakecloud-bootstrap.sh

# Compile the UDF against the running MySQL's plugin headers and drop
# it into the standard plugin dir. The runtime image ships
# mysql_config (or pkg-config + libmysqlclient-dev when on Debian).
RUN PLUGIN_DIR="$(mysql_config --plugindir 2>/dev/null || echo /usr/lib/mysql/plugin)" \
    && mkdir -p "$PLUGIN_DIR" \
    && CFLAGS="$(mysql_config --cflags 2>/dev/null || echo -I/usr/include/mysql)" \
    && gcc -O2 -fPIC -shared $CFLAGS -o "$PLUGIN_DIR/fakecloud_udf.so" \
        /tmp/fakecloud_udf.c -lcurl -lpthread \
    && rm /tmp/fakecloud_udf.c

# The bootstrap shell script substitutes FAKECLOUD_* env vars into the
# template SQL and drops the result into /docker-entrypoint-initdb.d/
# so the official mysql entrypoint picks it up on first start.
ENTRYPOINT ["fakecloud-bootstrap.sh"]
CMD ["mysqld"]
