# syntax=docker/dockerfile:1
FROM rust:latest AS builder

WORKDIR /app

# Cache dependencies with locked versions
COPY server/Cargo.toml server/Cargo.lock ./
RUN mkdir src && echo 'fn main() { println!("dummy"); }' > src/main.rs
RUN cargo build --release || true
RUN rm -rf src

# Build actual server binary
COPY server/src ./src
RUN touch src/main.rs && cargo build --release && strip target/release/voidvault-server

# Minimal hardened runtime
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged system user and group
RUN groupadd -g 10001 voidvault && \
    useradd -u 10001 -g voidvault -s /bin/false -M -d /data voidvault

# Persistent data directory
RUN mkdir -p /data && chown -R voidvault:voidvault /data

COPY --from=builder /app/target/release/voidvault-server /usr/local/bin/voidvault-server

ENV PORT=8080 \
    BIND_ADDR=0.0.0.0:8080 \
    DATABASE_PATH=/data/voidvault.db \
    RUST_LOG=info,tower_http=info

USER 10001:10001
WORKDIR /data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/voidvault-server"]
