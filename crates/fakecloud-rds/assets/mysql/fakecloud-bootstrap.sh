#!/usr/bin/env bash
# Render the FAKECLOUD_* env vars into the bootstrap SQL and drop the
# result into the standard mysql initdb directory before delegating to
# the upstream mysql entrypoint. The official image only sources files
# from /docker-entrypoint-initdb.d/ on first start (when the data dir
# is empty), which is exactly when we want the procedures created.
set -euo pipefail

ENDPOINT="${FAKECLOUD_ENDPOINT:-http://host.docker.internal:4566}"
ACCOUNT_ID="${FAKECLOUD_ACCOUNT_ID:-000000000000}"
REGION="${FAKECLOUD_REGION:-us-east-1}"

mkdir -p /docker-entrypoint-initdb.d
sed \
    -e "s|@FAKECLOUD_ENDPOINT@|${ENDPOINT}|g" \
    -e "s|@FAKECLOUD_ACCOUNT_ID@|${ACCOUNT_ID}|g" \
    -e "s|@FAKECLOUD_REGION@|${REGION}|g" \
    /tmp/99-fakecloud-bootstrap.sql.tmpl \
    > /docker-entrypoint-initdb.d/99-fakecloud-bootstrap.sql

exec docker-entrypoint.sh "$@"
