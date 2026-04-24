+++
title = "SES"
description = "Sending, templates, DKIM, suppression, and real inbound receipt rule execution."
weight = 14
+++

fakecloud implements **110 of 110** SES v2 operations at 100% Smithy conformance, plus SES v1 inbound receipt rule operations.

## Supported features

### Sending (SES v2)

- **SendEmail, SendBulkEmail** — recorded at `/_fakecloud/ses/emails`
- **Identities** — email identity and domain identity CRUD, DKIM, mail-from, feedback attributes, signing attributes
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

## Introspection

- `GET /_fakecloud/ses/emails` — list all sent emails with full body, headers, attachments
- `POST /_fakecloud/ses/inbound` — simulate receiving an inbound email, trigger receipt rule evaluation

## Cross-service delivery

- **SES -> SNS / EventBridge** — Send/delivery/bounce/complaint events fan out via configured event destinations
- **SES Inbound -> S3 / SNS / Lambda / Bounce / AddHeader / Stop** — Receipt rules evaluate and execute every supported action type

## Why this matters

LocalStack Community stores SES v1 inbound rules but never evaluates them. fakecloud actually runs the receipt rule pipeline — which means testing email-triggered workflows (rules that invoke a Lambda on an incoming email, rules that drop a message in S3, etc.) is possible end-to-end. That's a real differentiator for email-heavy testing.

## Source

- [`crates/fakecloud-ses`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-ses)
- [AWS SES v2 API reference](https://docs.aws.amazon.com/ses/latest/APIReference-V2/Welcome.html)
