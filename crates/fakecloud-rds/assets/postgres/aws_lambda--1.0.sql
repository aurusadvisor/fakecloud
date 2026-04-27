-- aws_lambda extension v1.0 (fakecloud)
-- Calls fakecloud Lambda invocations through a host bridge endpoint.

\echo Use "CREATE EXTENSION aws_lambda CASCADE" to load this file. \quit

CREATE FUNCTION aws_lambda.invoke(
    function_name text,
    payload json,
    region text DEFAULT NULL,
    invocation_type text DEFAULT 'RequestResponse'
) RETURNS TABLE(
    status_code integer,
    payload json,
    executed_version text,
    log_result text
)
LANGUAGE plpython3u
AS $$
import json
import os
import urllib.request
import urllib.error

endpoint = os.environ.get('FAKECLOUD_ENDPOINT')
if not endpoint:
    plpy.error('aws_lambda: FAKECLOUD_ENDPOINT not set on the database container')

account_id = os.environ.get('FAKECLOUD_ACCOUNT_ID', '000000000000')
default_region = os.environ.get('FAKECLOUD_REGION', 'us-east-1')

body = {
    'function_name': function_name,
    'payload': json.loads(payload) if payload is not None else None,
    'invocation_type': invocation_type,
    'region': region or default_region,
}

req = urllib.request.Request(
    endpoint.rstrip('/') + '/_fakecloud/rds/lambda-invoke',
    data=json.dumps(body).encode('utf-8'),
    headers={
        'Content-Type': 'application/json',
        'X-Fakecloud-Account-Id': account_id,
    },
    method='POST',
)

try:
    with urllib.request.urlopen(req, timeout=300) as resp:
        raw = resp.read()
except urllib.error.HTTPError as e:
    raw = e.read()
except Exception as e:
    plpy.error('aws_lambda: bridge call failed: {}'.format(e))

try:
    parsed = json.loads(raw)
except ValueError:
    plpy.error('aws_lambda: invalid bridge response: {!r}'.format(raw))

return [(
    int(parsed.get('status_code', 0)),
    json.dumps(parsed.get('payload')) if parsed.get('payload') is not None else None,
    parsed.get('executed_version'),
    parsed.get('log_result'),
)]
$$;

CREATE FUNCTION aws_lambda.invoke(
    function_name aws_commons._lambda_function_arn_1,
    payload json,
    region text DEFAULT NULL,
    invocation_type text DEFAULT 'RequestResponse'
) RETURNS TABLE(
    status_code integer,
    payload json,
    executed_version text,
    log_result text
)
LANGUAGE plpgsql
AS $$
DECLARE
    name text;
BEGIN
    name := (function_name).function_name;
    IF (function_name).qualifier IS NOT NULL THEN
        name := name || ':' || (function_name).qualifier;
    END IF;
    RETURN QUERY SELECT * FROM aws_lambda.invoke(name, payload, region, invocation_type);
END;
$$;
