+++
title = "SES"
description = "Sending, templates, DKIM, suppression, and real inbound receipt rule execution."
weight = 14
+++

fakecloud implements **110 of 110** SES v2 operations at 100% Smithy conformance, plus SES v1 inbound receipt rule operations.

## Supported features

### Sending (SES v2)

- **SendEmail, SendBulkEmail** — recorded at `/_fakecloud/ses/emails`, including the stamped `DKIM-Signature` header when signing is enabled
- **Identities** — email identity and domain identity CRUD, DKIM (real RSA-SHA256 signing with relaxed/relaxed canonicalization), mail-from, feedback attributes, signing attributes
- **Configuration sets** — CRUD, event destinations, reputation options, sending options, tracking, suppression, VDM, archiving
- **Templates** — email templates, custom verification templates, test rendering
- **Contact lists** — CRUD, contacts, subscription topics
- **Dedicated IPs** — pools, warmup, scaling
- **Suppression list** — CRUD, account-level suppression
- **Event destinations** — fan out to SNS and EventBridge on send/delivery/bounce/complaint
- **Import and export jobs** — CRUD
- **Multi-region endpoints** — CRUD
- **Tenants** — multi-tenant isolation
- **Reputation** — entity management, policy

### Inbound (SES v1)

- **Receipt rule sets** — CRUD, active rule set management
- **Receipt rules** — CRUD, scan rules
- **Receipt filters** — IP filters
- **Real inbound pipeline** — `/_fakecloud/ses/inbound` simulates receiving an email, evaluates receipt rules, and **actually executes** the configured actions:
  - **S3 action** — writes the (header-augmented) message to the bucket
  - **SNS action** — publishes a `Received` notification to the topic
  - **Lambda action** — invokes the function with the `aws:ses` event envelope
  - **AddHeader action** — prepends headers to the message before downstream actions see it
  - **Bounce action** — enqueues a bounce email back to the sender (visible at `/_fakecloud/ses/emails`) and publishes a `Bounce` notification to the optional topic
  - **Stop action** — halts subsequent rules; publishes a notification when a topic is configured

## Protocol

SES v2 uses REST. SES v1 inbound uses Query protocol.

## SMTP submission

fakecloud also exposes a minimal SMTP submission listener that mirrors `email-smtp.<region>.amazonaws.com:587`. It is **off by default** — set `FAKECLOUD_SES_SMTP_PORT=2525` (or any free port) before starting the server to enable it.

- Authenticate with credentials produced by IAM `CreateServiceSpecificCredential` for `ServiceName=ses.amazonaws.com` (the `ServiceUserName` / `ServicePassword` pair from the response).
- Both `AUTH PLAIN` and `AUTH LOGIN` mechanisms are supported.
- After `MAIL FROM` / `RCPT TO` / `DATA`, the message is recorded in the SES `sent_emails` ledger as a `SentEmail` with `raw_data` populated, mirroring `SendRawEmail`. It then surfaces on `GET /_fakecloud/ses/emails` like any other accepted message.
- STARTTLS is not implemented — keep the listener bound to localhost in tests.

## Introspection

- `GET /_fakecloud/ses/emails` — list all sent emails with full body, synthesized headers (DKIM-Signature first when signing was active), attachments
- `GET /_fakecloud/ses/identities/{name}/dkim-public-key` — pull the published Easy DKIM public key (SPKI DER, base64) so tests can verify signatures end-to-end
- `POST /_fakecloud/ses/inbound` — simulate receiving an inbound email, trigger receipt rule evaluation

## Cross-service delivery

- **SES -> SNS / EventBridge** — Send/delivery/bounce/complaint events fan out via configured event destinations
- **SES Inbound -> S3 / SNS / Lambda / Bounce / AddHeader / Stop** — Receipt rules evaluate and execute every supported action type

## Why this matters

LocalStack Community stores SES v1 inbound rules but never evaluates them. fakecloud actually runs the receipt rule pipeline — which means testing email-triggered workflows (rules that invoke a Lambda on an incoming email, rules that drop a message in S3, etc.) is possible end-to-end. That's a real differentiator for email-heavy testing.

## Source

- [`crates/fakecloud-ses`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-ses)
- [AWS SES v2 API reference](https://docs.aws.amazon.com/ses/latest/APIReference-V2/Welcome.html)
