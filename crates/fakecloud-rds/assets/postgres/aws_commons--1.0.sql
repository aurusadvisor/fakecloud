-- aws_commons extension v1.0 (fakecloud)
-- Provides composite types and helpers used by aws_lambda and aws_s3 RDS extensions.

\echo Use "CREATE EXTENSION aws_commons" to load this file. \quit

CREATE TYPE aws_commons._lambda_function_arn_1 AS (
    function_name text,
    qualifier text
);

CREATE FUNCTION aws_commons.create_lambda_function_arn(
    function_name text,
    qualifier text DEFAULT NULL
) RETURNS aws_commons._lambda_function_arn_1
LANGUAGE plpgsql IMMUTABLE
AS $$
DECLARE
    result aws_commons._lambda_function_arn_1;
BEGIN
    result.function_name := function_name;
    result.qualifier := qualifier;
    RETURN result;
END;
$$;
