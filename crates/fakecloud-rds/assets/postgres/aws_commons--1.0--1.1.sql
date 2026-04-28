-- aws_commons 1.0 -> 1.1 upgrade (fakecloud)
-- Adds the `_s3_uri_1` composite type and `create_s3_uri()` constructor
-- consumed by the aws_s3 extension. Loaded automatically by
-- `ALTER EXTENSION aws_commons UPDATE` for users that already have 1.0.

\echo Use "ALTER EXTENSION aws_commons UPDATE TO '1.1'" to load this file. \quit

CREATE TYPE aws_commons._s3_uri_1 AS (
    bucket text,
    file_path text,
    region text
);

CREATE FUNCTION aws_commons.create_s3_uri(
    bucket text,
    file_path text,
    region text DEFAULT NULL
) RETURNS aws_commons._s3_uri_1
LANGUAGE plpgsql IMMUTABLE
AS $$
DECLARE
    result aws_commons._s3_uri_1;
BEGIN
    result.bucket := bucket;
    result.file_path := file_path;
    result.region := region;
    RETURN result;
END;
$$;
