-- aws_s3 extension v1.0 (fakecloud)
-- Imports objects from a fakecloud S3 bucket into postgres tables
-- (`table_import_from_s3`) and exports query results back into S3
-- (`query_export_to_s3`). Talks to fakecloud over the bridge endpoints
-- /_fakecloud/rds/s3-import and /_fakecloud/rds/s3-export.

\echo Use "CREATE EXTENSION aws_s3 CASCADE" to load this file. \quit

-- Internal helper: GET <bucket>/<key> via the bridge, write the body
-- to a temp file, return the temp path and total bytes.
CREATE FUNCTION aws_s3._fetch_object(
    bucket text,
    file_path text,
    region text
) RETURNS TABLE(temp_path text, bytes_processed bigint)
LANGUAGE plpython3u
AS $$
import base64
import json
import os
import tempfile
import urllib.request
import urllib.error

endpoint = os.environ.get('FAKECLOUD_ENDPOINT')
if not endpoint:
    plpy.error('aws_s3: FAKECLOUD_ENDPOINT not set on the database container')
account_id = os.environ.get('FAKECLOUD_ACCOUNT_ID', '000000000000')
default_region = os.environ.get('FAKECLOUD_REGION', 'us-east-1')

body = json.dumps({
    'bucket': bucket,
    'key': file_path,
    'region': region or default_region,
}).encode('utf-8')

req = urllib.request.Request(
    endpoint.rstrip('/') + '/_fakecloud/rds/s3-import',
    data=body,
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
    detail = e.read().decode('utf-8', errors='replace')
    plpy.error('aws_s3: s3-import bridge returned {}: {}'.format(e.code, detail))
except Exception as e:
    plpy.error('aws_s3: s3-import bridge call failed: {}'.format(e))

parsed = json.loads(raw)
data = base64.b64decode(parsed['body_b64'])

fd, path = tempfile.mkstemp(prefix='aws_s3_', suffix='.dat', dir='/tmp')
try:
    with os.fdopen(fd, 'wb') as fh:
        fh.write(data)
except Exception:
    os.unlink(path)
    raise

return [(path, len(data))]
$$;

CREATE FUNCTION aws_s3.table_import_from_s3(
    table_name text,
    column_list text,
    options text,
    bucket text,
    file_path text,
    region text DEFAULT NULL
) RETURNS TABLE(rows_imported bigint, file_compression text, bytes_processed bigint)
LANGUAGE plpgsql
AS $$
DECLARE
    fetched record;
    column_clause text;
    options_clause text;
    copy_sql text;
    inserted_rows bigint;
BEGIN
    SELECT * INTO fetched FROM aws_s3._fetch_object(bucket, file_path, region);

    IF column_list IS NOT NULL AND length(trim(column_list)) > 0 THEN
        column_clause := format(' (%s)', column_list);
    ELSE
        column_clause := '';
    END IF;

    IF options IS NOT NULL AND length(trim(options)) > 0 THEN
        options_clause := format(' WITH (%s)', options);
    ELSE
        options_clause := '';
    END IF;

    copy_sql := format(
        'COPY %s%s FROM %L%s',
        table_name,
        column_clause,
        fetched.temp_path,
        options_clause
    );

    BEGIN
        EXECUTE copy_sql;
        GET DIAGNOSTICS inserted_rows = ROW_COUNT;
    EXCEPTION WHEN OTHERS THEN
        PERFORM aws_s3._cleanup_temp(fetched.temp_path);
        RAISE;
    END;

    PERFORM aws_s3._cleanup_temp(fetched.temp_path);
    RETURN QUERY SELECT inserted_rows, ''::text, fetched.bytes_processed;
END;
$$;

CREATE FUNCTION aws_s3.table_import_from_s3(
    table_name text,
    column_list text,
    options text,
    s3_info aws_commons._s3_uri_1
) RETURNS TABLE(rows_imported bigint, file_compression text, bytes_processed bigint)
LANGUAGE SQL
AS $$
    SELECT * FROM aws_s3.table_import_from_s3(
        table_name,
        column_list,
        options,
        (s3_info).bucket,
        (s3_info).file_path,
        (s3_info).region
    );
$$;

CREATE FUNCTION aws_s3._cleanup_temp(path text) RETURNS void
LANGUAGE plpython3u
AS $$
import os
try:
    os.unlink(path)
except FileNotFoundError:
    pass
$$;

-- Internal helper: read a temp file produced by `COPY ... TO`, base64
-- encode it, and PUT it through the bridge to the target bucket/key.
CREATE FUNCTION aws_s3._upload_object(
    bucket text,
    file_path text,
    region text,
    temp_path text
) RETURNS TABLE(rows_uploaded bigint, files_uploaded bigint, bytes_uploaded bigint)
LANGUAGE plpython3u
AS $$
import base64
import json
import os
import urllib.request
import urllib.error

endpoint = os.environ.get('FAKECLOUD_ENDPOINT')
if not endpoint:
    plpy.error('aws_s3: FAKECLOUD_ENDPOINT not set on the database container')
account_id = os.environ.get('FAKECLOUD_ACCOUNT_ID', '000000000000')
default_region = os.environ.get('FAKECLOUD_REGION', 'us-east-1')

with open(temp_path, 'rb') as fh:
    raw = fh.read()

body = json.dumps({
    'bucket': bucket,
    'key': file_path,
    'region': region or default_region,
    'body_b64': base64.b64encode(raw).decode('ascii'),
}).encode('utf-8')

req = urllib.request.Request(
    endpoint.rstrip('/') + '/_fakecloud/rds/s3-export',
    data=body,
    headers={
        'Content-Type': 'application/json',
        'X-Fakecloud-Account-Id': account_id,
    },
    method='POST',
)
try:
    with urllib.request.urlopen(req, timeout=300) as resp:
        parsed = json.loads(resp.read())
except urllib.error.HTTPError as e:
    detail = e.read().decode('utf-8', errors='replace')
    plpy.error('aws_s3: s3-export bridge returned {}: {}'.format(e.code, detail))
except Exception as e:
    plpy.error('aws_s3: s3-export bridge call failed: {}'.format(e))

# rows_uploaded is filled by the SQL caller from GET DIAGNOSTICS; the
# bridge only knows bytes. files_uploaded is always 1 (single PutObject).
return [(0, 1, int(parsed.get('bytes_uploaded', len(raw))))]
$$;

CREATE FUNCTION aws_s3.query_export_to_s3(
    query text,
    bucket text,
    file_path text,
    region text DEFAULT NULL,
    options text DEFAULT NULL
) RETURNS TABLE(rows_uploaded bigint, files_uploaded bigint, bytes_uploaded bigint)
LANGUAGE plpgsql
AS $$
DECLARE
    options_clause text;
    copy_sql text;
    temp_path text;
    exported_rows bigint;
    upload record;
BEGIN
    IF options IS NOT NULL AND length(trim(options)) > 0 THEN
        options_clause := format(' WITH (%s)', options);
    ELSE
        options_clause := '';
    END IF;

    -- Use a stable, unique path so we can pass it to COPY (which needs a
    -- string literal) and then read it back from plpython3u.
    temp_path := format('/tmp/aws_s3_export_%s.dat', floor(random() * 1e12)::bigint);
    copy_sql := format('COPY (%s) TO %L%s', query, temp_path, options_clause);

    BEGIN
        EXECUTE copy_sql;
        GET DIAGNOSTICS exported_rows = ROW_COUNT;
        SELECT * INTO upload FROM aws_s3._upload_object(bucket, file_path, region, temp_path);
    EXCEPTION WHEN OTHERS THEN
        PERFORM aws_s3._cleanup_temp(temp_path);
        RAISE;
    END;

    PERFORM aws_s3._cleanup_temp(temp_path);
    RETURN QUERY SELECT exported_rows, upload.files_uploaded, upload.bytes_uploaded;
END;
$$;

CREATE FUNCTION aws_s3.query_export_to_s3(
    query text,
    s3_info aws_commons._s3_uri_1,
    options text DEFAULT NULL
) RETURNS TABLE(rows_uploaded bigint, files_uploaded bigint, bytes_uploaded bigint)
LANGUAGE SQL
AS $$
    SELECT * FROM aws_s3.query_export_to_s3(
        query,
        (s3_info).bucket,
        (s3_info).file_path,
        (s3_info).region,
        options
    );
$$;
