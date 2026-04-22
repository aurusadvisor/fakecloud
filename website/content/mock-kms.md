+++
title = "Mock KMS for tests"
description = "Mock AWS KMS locally for integration tests with fakecloud. 53 KMS operations, real ECDH, encryption/decryption, aliases, grants, key import, multi-region keys. Any AWS SDK, free."
template = "page.html"
+++

Need to mock AWS KMS for integration tests? Use [fakecloud](https://github.com/faiscadev/fakecloud).

```sh
curl -fsSL https://raw.githubusercontent.com/faiscadev/fakecloud/main/install.sh | bash
fakecloud
```

Point your AWS SDK at `http://localhost:4566`.

## Why fakecloud for KMS

- **53 KMS operations** at 100% conformance — symmetric and asymmetric keys, encrypt/decrypt, aliases, grants, data key generation, real ECDH, key import, multi-region keys, key policies.
- **Real cryptography.** Encrypt/decrypt operations use real AES-GCM / RSA / ECDSA / ECDH primitives. Output ciphertexts are cryptographically meaningful, not opaque stubs.
- **Any AWS SDK in any language.** Real HTTP server on port 4566.
- **KMS key policies enforced.** Opt-in `--iam strict` mode validates key-policy Principal/Condition semantics with AWS's cross-account combining rules.
- **No account, no auth token, no paid tier.** AGPL-3.0.

## Quick examples

### Python (boto3)

```python
import boto3
kms = boto3.client('kms',
    endpoint_url='http://localhost:4566',
    aws_access_key_id='test',
    aws_secret_access_key='test',
    region_name='us-east-1')

key = kms.create_key(Description='test-key')
key_id = key['KeyMetadata']['KeyId']

ct = kms.encrypt(KeyId=key_id, Plaintext=b'secret data')
pt = kms.decrypt(KeyId=key_id, CiphertextBlob=ct['CiphertextBlob'])
assert pt['Plaintext'] == b'secret data'
```

### AWS CLI

```sh
aws --endpoint-url http://localhost:4566 kms create-key --description "test-key"
aws --endpoint-url http://localhost:4566 kms encrypt \
  --key-id <key-id> --plaintext "hello world" --query CiphertextBlob --output text
```

## Aliases

```sh
aws --endpoint-url http://localhost:4566 kms create-alias \
  --alias-name alias/my-key --target-key-id <key-id>

aws --endpoint-url http://localhost:4566 kms encrypt \
  --key-id alias/my-key --plaintext "hello"
```

## Data keys

```python
dk = kms.generate_data_key(KeyId=key_id, KeySpec='AES_256')
# dk['Plaintext']      -> raw 32-byte key for local encryption
# dk['CiphertextBlob'] -> encrypted version to store with data
```

Used in envelope-encryption flows. Real AES-GCM throughout.

## Asymmetric + ECDH

```python
asym = kms.create_key(KeySpec='ECC_NIST_P256', KeyUsage='KEY_AGREEMENT')
# Real ECDH key agreement for end-to-end tests
```

## SSE-KMS on S3

```sh
aws --endpoint-url http://localhost:4566 s3 cp file.txt s3://bucket/file.txt \
  --sse aws:kms --sse-kms-key-id alias/my-key
```

Object encrypted at rest with the specified KMS key. Retrieval decrypts transparently.

## Secrets Manager + KMS

Secrets Manager secrets are encrypted with KMS by default. Rotation via Lambda works end-to-end (Lambda runs real code, calls KMS to re-encrypt).

## How it differs from alternatives

| Tool | Multi-language | Real crypto | SSE-KMS on S3 | Key policies |
|---|---|---|---|---|
| fakecloud | Any | Yes (AES-GCM, RSA, ECDSA, ECDH) | Yes | Yes (Principal/Condition) |
| LocalStack Community | Any (auth required) | Partial | Yes | Partial |
| Moto (mock_kms) | Python only | Partial | Stubbed | Partial |
| aws-encryption-sdk | N/A | N/A | N/A (client-side only) | N/A |

## Links

- **Install:** `curl -fsSL https://raw.githubusercontent.com/faiscadev/fakecloud/main/install.sh | bash`
- **Repo:** [github.com/faiscadev/fakecloud](https://github.com/faiscadev/fakecloud)
- **Related:** [Fake AWS server for tests](/fake-aws-server/), [Local S3 for integration tests](/local-s3-for-tests/)
