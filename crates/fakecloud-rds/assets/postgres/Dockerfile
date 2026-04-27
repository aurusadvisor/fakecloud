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
