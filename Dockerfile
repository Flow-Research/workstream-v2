FROM rust:1.92-slim AS builder

WORKDIR /app

# Cache dependencies separately for faster rebuilds
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY src ./src

RUN cargo build --release --workspace

FROM debian:bookworm-slim

# Minimal runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/sequencer /usr/local/bin/workstream-sequencer
COPY --from=builder /app/target/release/prover /usr/local/bin/workstream-prover
COPY --from=builder /app/target/release/node /usr/local/bin/workstream-node

COPY config ./config

# Sequencer RPC, Prover API, Node P2P
EXPOSE 8545 8080 30303

CMD ["workstream-node"]
