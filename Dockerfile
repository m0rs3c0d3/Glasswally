# Multi-stage build for Glasswally
# Stage 1: build
FROM rust:1.82-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependencies first
COPY Cargo.toml Cargo.lock ./
COPY glasswally/Cargo.toml ./glasswally/
COPY xtask/Cargo.toml ./xtask/

RUN mkdir -p glasswally/src xtask/src && \
    echo "fn main(){}" > glasswally/src/main.rs && \
    echo "fn main(){}" > xtask/src/main.rs && \
    cargo build --release -p glasswally --locked 2>/dev/null || true

# Build real binary
COPY glasswally/src ./glasswally/src
RUN cargo build --release -p glasswally --locked

# Stage 2: runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl libssl3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/glasswally /usr/local/bin/glasswally

RUN useradd -r -s /bin/false glasswally && \
    mkdir -p /output && chown glasswally /output

USER glasswally
ENTRYPOINT ["glasswally"]
