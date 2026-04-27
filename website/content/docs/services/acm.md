+++
title = "ACM"
description = "AWS Certificate Manager — request / import / export / revoke certificates, tags, account configuration. JSON 1.1 protocol."
weight = 26
+++

fakecloud implements AWS Certificate Manager's full JSON 1.1 control plane: 17 operations covering certificate lifecycle, import/export, tags, and account-wide expiry events. 100% Smithy conformance.

**Status: 100% control-plane coverage.**

## Supported today

- **Public certificate lifecycle** — `RequestCertificate` accepts `DomainName`, `SubjectAlternativeNames`, `ValidationMethod` (DNS / EMAIL), `IdempotencyToken`, `KeyAlgorithm`, `Options`, `CertificateAuthorityArn`, `ManagedBy`, `Tags`. The certificate lands at `PENDING_VALIDATION` with `Type = AMAZON_ISSUED`. Idempotency: a request re-issued with the same `IdempotencyToken` + `DomainName` + SANs returns the same `CertificateArn`. `DescribeCertificate` returns the full `CertificateDetail` including domain validation, options, key usages, ARN, status, validity window. `GetCertificate` returns deterministic placeholder PEM strings for the cert + chain. `ListCertificates` supports `MaxItems` + `NextToken` + `CertificateStatuses` + `Includes.keyTypes`. `SearchCertificates` honors `FilterStatement.Filter.KeyTypes` (And/Or/Not composition is parsed but ignored). `DeleteCertificate` rejects with `ResourceInUseException` while `InUseBy` is non-empty.
- **Imported certificates** — `ImportCertificate` accepts the PEM cert + private key + optional chain (base64-encoded over the wire), stores them, and flips `Status` to `ISSUED` with `Type = IMPORTED`. Passing an existing `CertificateArn` re-imports in place (the cert must already be `IMPORTED`). `ExportCertificate` requires a `Passphrase`, returns the stored cert + chain + private key. Imported certs are not eligible for `RevokeCertificate` (`InvalidParameterException`) or `RenewCertificate`.
- **Renewal + revocation** — `RenewCertificate` (AMAZON_ISSUED only) bumps `NotBefore`/`NotAfter` by 13 months and flips status to `ISSUED`. `RevokeCertificate` requires `RevocationReason`, sets `Status = REVOKED` and stamps `RevokedAt`.
- **Email validation** — `ResendValidationEmail` is only valid when `ValidationMethod = EMAIL`; DNS-validated certs return `InvalidParameterException`.
- **Tags** — `AddTagsToCertificate` upserts tags by key, `RemoveTagsFromCertificate` deletes by key (optionally also matching value), `ListTagsForCertificate` returns the tag set sorted by key for deterministic test output.
- **Account configuration** — `PutAccountConfiguration` accepts `IdempotencyToken` + `ExpiryEvents.DaysBeforeExpiry`; `GetAccountConfiguration` returns it back.
- **Certificate options** — `UpdateCertificateOptions` updates `CertificateTransparencyLoggingPreference` and `Export`.

## Smoke test

```sh
fakecloud &

ARN=$(aws --endpoint-url http://localhost:4566 acm request-certificate \
  --domain-name api.example.com \
  --validation-method DNS \
  --query CertificateArn --output text)

aws --endpoint-url http://localhost:4566 acm describe-certificate \
  --certificate-arn "$ARN"

aws --endpoint-url http://localhost:4566 acm add-tags-to-certificate \
  --certificate-arn "$ARN" \
  --tags Key=env,Value=prod

aws --endpoint-url http://localhost:4566 acm list-tags-for-certificate \
  --certificate-arn "$ARN"
```

## Caveats

fakecloud does not run the real X.509 validation pipeline. Certificates requested via `RequestCertificate` stay at `PENDING_VALIDATION` until you call `RenewCertificate`; the synthesized DNS validation `ResourceRecord` is deterministic per domain but is never observed by a real ACM validator. `ImportCertificate` does not parse the input X.509 cert — it stores the bytes verbatim and uses the cheap `CN=` substring scan to extract `DomainName`. `ExportCertificate` returns the imported cert as-is when one exists or a placeholder PEM otherwise; the passphrase is required but not used to encrypt the output. `KeyUsages` and `ExtendedKeyUsages` reported by `DescribeCertificate` are constants (`DIGITAL_SIGNATURE` + `KEY_ENCIPHERMENT`, TLS server + client auth) — fakecloud does not extract them from imported certs.
