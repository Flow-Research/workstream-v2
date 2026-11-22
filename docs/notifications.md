# Verified-event notifications

Issue #137: verified chain events that carry an operator decision (independent
review decisions and finalized acceptances) reach opted-in notification
recipients through a durable delivery outbox.

## Model

- The node enqueues events after checking the block proof and before advancing
  its in-memory tip. Replaying a block uses the same delivery identities.
- Before any notification provider is contacted, the event is durably recorded
  in the outbox (`crates/workstream-ops/src/notifications.rs`, SQLite at
  `WORKSTREAM_NOTIFICATIONS_DB`, default `<runtime>/notifications.sqlite`).
- Outbound content is public decision metadata plus a canonical status link.
  Notifications never embed witnesses, signing material, raw payloads or private
  evidence bytes.
- The delivery identity is a domain-separated SHA-256 over `WS:v1:notif:dl:v1`,
  event type, recipient, chain, height, transaction index and subject. Delivery
  is at least once: receivers must deduplicate by delivery ID before acting.
- Failed deliveries return to `pending` and are retried with exponential backoff
  (30s doubling, capped at 3600s). Delivered and opted-out outcomes are
  terminal.

## Delivery

- Sinks implement `DeliverySink`. The built-in sink signs each delivery with
  HMAC-SHA256 over `delivery_id.timestamp.body` and sends it as a JSON webhook
  with `X-Workstream-Delivery`, `X-Workstream-Timestamp` (Unix seconds) and `X-Workstream-Signature: sha256=<hex>`
  headers. The signature timestamp tolerance is five minutes and comparison is
  constant time.
- Operators configure the subscriber set with
  `WORKSTREAM_NOTIFICATION_SUBSCRIBERS` (JSON array of recipient identifiers).
  An empty or missing set disables delivery.
- Operators configure the webhook with
  `WORKSTREAM_NOTIFICATION_WEBHOOK_URL` and
  `WORKSTREAM_NOTIFICATION_WEBHOOK_SECRET`. Use HTTPS and a random secret of at least 32 bytes.

## Process wiring

The connected node opens the outbox, attaches it via `Node::with_notifications`,
and spawns the consumer task
(`workstream_ops::notifications::run`). The consumer claims due deliveries on a
timer, dispatches them to the configured sink, and records the outcome.

The consumer task participates in the node's runtime `tokio::select!` loop.
When no webhook is configured the consumer stays idle and delivery stays
dormant.
