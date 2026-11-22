FROM rust:1.92-slim-bookworm AS builder
WORKDIR /app
COPY . .
ENV CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0
RUN cargo build --locked --bin sequencer --bin node --bin prover --bin workstream-reindex && \
    cargo run --locked -p workstream-tests --example connected_fixture > /app/signed-fixture.json

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl python3 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/debug/node /usr/local/bin/workstream-node
COPY --from=builder /app/target/debug/sequencer /usr/local/bin/workstream-sequencer
COPY --from=builder /app/target/debug/prover /usr/local/bin/workstream-prover
COPY --from=builder /app/target/debug/workstream-reindex /usr/local/bin/workstream-reindex
COPY --from=builder /app/signed-fixture.json ./signed-fixture.json
COPY scripts/dev-service-identities.sh ./
COPY config ./config
USER 10001:10001
CMD ["workstream-node"]
