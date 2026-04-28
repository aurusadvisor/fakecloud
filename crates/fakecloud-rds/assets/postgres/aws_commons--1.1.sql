-- aws_commons extension v1.1 (fakecloud)
-- Provides composite types and helpers used by aws_lambda and aws_s3 RDS extensions.

\echo Use "CREATE EXTENSION aws_commons" to load this file. \quit

CREATE TYPE aws_commons._lambda_function_arn_1 AS (
    function_name text,
    region text
);

CREATE FUNCTION aws_commons.create_lambda_function_arn(
    function_name text,
    region text DEFAULT NULL
) RETURNS aws_commons._lambda_function_arn_1
LANGUAGE plpgsql IMMUTABLE
AS $$
DECLARE
    result aws_commons._lambda_function_arn_1;
BEGIN
    result.function_name := function_name;
    result.region := region;
    RETURN result;
END;
$$;

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
