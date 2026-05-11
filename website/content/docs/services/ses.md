+++
title = "SES"
description = "Sending, templates, DKIM, suppression, and real inbound receipt rule execution."
weight = 14
+++

fakecloud implements **110 of 110** SES v2 operations at 100% Smithy conformance, plus SES v1 inbound receipt rule operations.

## Supported features

### Sending (SES v2)

- **SendEmail, SendBulkEmail** — recorded at `/_fakecloud/ses/emails`, including the stamped `DKIM-Signature` header when signing is enabled
- **SendBounce (v1)** — synthesise an inbound bounce message; the bounce record lands in `/_fakecloud/ses/emails` and triggers configured event destinations
- **Identities** — email identity and domain identity CRUD, real DKIM RSA-SHA256 signing with relaxed/relaxed canonicalization (public key served at `/_fakecloud/ses/identities/{name}/dkim-public-key`), mail-from, feedback attributes, signing attributes
- **Configuration sets** — CRUD, event destinations, reputation options, sending options, tracking, suppression, VDM, archiving
- **Templates** — email templates, custom verification templates, and `TestRenderEmailTemplate` which produces a full RFC 5322 / MIME message (Subject, From, To, CC, BCC, Reply-To, Date, Message-ID, multipart bodies, attachments) from the stored template + JSON template data
- **Contact lists** — CRUD, contacts, subscription topics
- **Dedicated IPs** — pools, warmup, scaling
- **Suppression list** — CRUD, account-level suppression
- **Event destinations** — fan out to **SNS, EventBridge, Kinesis Data Streams, Kinesis Data Firehose, and CloudWatch** on send/delivery/bounce/complaint/click/open/reject/rendering-failure
- **GetMessageInsights** — per-message delivery / engagement timeline (send + delivery + bounce + complaint + open + click events) keyed by `MessageId`
- **Import and export jobs** — CRUD
- **Multi-region endpoints** — CRUD
- **Tenants** — multi-tenant isolation
- **Reputation** — entity management, policy

### Deliverability simulator addresses

fakecloud honours the standard [AWS mailbox simulator](https://docs.aws.amazon.com/ses/latest/dg/send-email-simulator.html) recipients on `SendEmail` / `SendRawEmail` / `SendBulkEmail`:

- `bounce@simulator.amazonses.com` -> synthetic hard bounce + `Bounce` event
- `complaint@simulator.amazonses.com` -> synthetic complaint event
- `suppressionlist@simulator.amazonses.com` -> account suppression hit
- `success@simulator.amazonses.com` -> normal `Delivery` event
- `ooto@simulator.amazonses.com` -> out-of-office auto-reply

Events fan out through the configuration set's event destinations exactly like a real send.

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

## SMTP outbound relay (opt-in)

For tests that want fakecloud to forward accepted messages out to a real SMTP server (for example [MailHog](https://github.com/mailhog/MailHog) or your own integration mailbox), set `FAKECLOUD_SES_SMTP_RELAY=smtp://host:port` before starting the server. When set, fakecloud will dispatch every accepted `SendEmail` / `SendRawEmail` / `SendBulkEmail` / SMTP-submitted message to the configured relay in addition to recording it locally.

- **Opt-in only.** With the variable unset, no outbound network traffic is generated — messages are recorded in memory like before.
- Failures from the relay are logged but do not fail the send (the message is still recorded), matching SES's "accepted for delivery" semantics.

## Introspection

- `GET /_fakecloud/ses/emails` — list all sent emails with full body, synthesized headers (DKIM-Signature first when signing was active), attachments
- `GET /_fakecloud/ses/metrics` — counters (e.g. `suppressedDropsTotal`) for the SES emulator
- `GET /_fakecloud/ses/identities/{name}/dkim-public-key` — pull the published Easy DKIM public key (SPKI DER, base64) so tests can verify signatures end-to-end
- `POST /_fakecloud/ses/identities/{name}/mail-from-status` — override an identity's MAIL FROM domain verification status (`NotStarted` / `Pending` / `Success` / `Failed`)
- `POST /_fakecloud/ses/account/sandbox` — toggle account-level sandbox / production access state for sending checks
- `POST /_fakecloud/ses/inbound` — simulate receiving an inbound email, trigger receipt rule evaluation

The introspection SDKs (Go/TypeScript/Python/Java/PHP) wrap each of these as a one-line helper, e.g. `fc.ses().getDkimPublicKey("example.com")`, `fc.ses().setSandbox(false)`.

## Cross-service delivery

- **SES -> SNS / EventBridge / Kinesis Data Streams / Kinesis Data Firehose / CloudWatch** — Send/delivery/bounce/complaint/click/open/reject/rendering-failure events fan out via configured event destinations
- **SES Inbound -> S3 / SNS / Lambda / Bounce / AddHeader / Stop / Workmail** — Receipt rules evaluate and execute every supported action type

## Why this matters

LocalStack Community stores SES v1 inbound rules but never evaluates them. fakecloud actually runs the receipt rule pipeline — which means testing email-triggered workflows (rules that invoke a Lambda on an incoming email, rules that drop a message in S3, etc.) is possible end-to-end. That's a real differentiator for email-heavy testing.

## Source

- [`crates/fakecloud-ses`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-ses)
- [AWS SES v2 API reference](https://docs.aws.amazon.com/ses/latest/APIReference-V2/Welcome.html)
