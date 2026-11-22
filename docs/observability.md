# Observability: tracing a transaction and detecting stalls (issue #129)

## Decision record

### Correlation model

A transaction's signed hash is immutable from admission through verification.
Every service derives the same **W3C trace id** from that hash with
`opentelemetry::trace::TraceId`, using a domain-separated SHA-256 of the hash.
A per-stage span id is derived from the same hash plus a fixed stage name
(`admit`, `prove`, `verify`), so the three spans share a trace but never
collide. The derivation lives in `crates/workstream-ops/src/trace.rs`.

This design has two security properties:

1. **Unforgeable correlation.** A caller cannot inject another transaction's
   trace id. The id is a one-way function of the hash the writer actually
   admitted, and the role label is a compile-time/static environment value,
   never a request field.
2. **No sensitive material in telemetry.** The only ids fed into the
   correlation module are public hashes (transaction, DA reference,
   commitment). `Transaction`, `ProveBlockTransition` (which carries the
   backend witness), `Witness`, `ShieldedNote` (blinding), object-DA
   credentials and database passwords are never passed to `tracing` fields or
   the metrics endpoint.

When `WORKSTREAM_LOG_FORMAT=json`, the tracing layer emits structured events
with `trace_id`, `span_id`, `service` on the span and safe domain hashes as
event fields. Operators can join a transaction across all four processes on
`trace_id` alone. The `traceparent()` helper produces the standard
`00-<trace>-<span>-01` value for an OpenTelemetry collector.

### Liveness vs readiness

- `/livez` (and the legacy `/healthz`) answer 200 whenever the process can
  serve. They deliberately ignore dependency state so a correctly waiting
  process is never restarted.
- `/readyz` returns 503 unless the component called `heartbeat(true)` within
  the last 30 seconds. A stalled DA, absent prover or unavailable writer
  fails readiness, not liveness.

### Five stall categories

| Category | Metric | Signal source |
| --- | --- | --- |
| Admission backlog | `workstream_admission_backlog` | sequencer mempool depth |
| Proof delay | `workstream_proof_delay_ms` | age of the oldest queued proof job |
| DA failure | `workstream_da_failures_total` | writer publish and node fetch retry failures |
| Verification rejection | `workstream_verification_rejections_total` | blocks rejected by the verifier |
| Index lag | `workstream_index_lag_blocks` | verified minus indexed height |

`config/prometheus-alerts.yml` defines one alert per category plus the
component/availability and RPC-error alerts. `config/grafana-dashboard.json`
gives each category its own panel and plots liveness against readiness.
`config/prometheus.yml` scrapes the three loopback metrics ports with a static
`service` label; nothing labels from an untrusted request.

## Verification

`scripts/test-observability.py` is a deterministic process drill:

1. Reaches a verified receipt for a signed transaction and asserts the
   transaction hash appears in correlated JSON logs.
2. Asserts every stall series is typed on every service and that `/livez`
   stays healthy.
3. Removes the DA provider, asserts the DA-failure counter crosses the alert
   threshold while the verified tip is held, and confirms no liveness flip.
4. Restores the provider and confirms the second block verifies and the
   counter settles.
5. Scans all service logs for sentinel access/secret keys and for witness,
   blinding, private-key and payload labels; none may appear.

## Residual gaps

- The local drill evaluates alert conditions directly against scraped metric
  values. A hosted Prometheus/Grafana deployment is not provisioned by this
  repository; the scrape rule, alert rules and dashboard JSON are provided for
  the operator's collector.
- Hosted CI does not run the process-level DA-stall drill; it is local
  deterministic evidence, like the other crash/restart drills.
- Trace ids are derived from hashes rather than sampled end-to-end spans; the
  model gives deterministic correlation but does not export span latency
  histograms to an OTLP collector. Adding an OTLP exporter is a follow-up.
