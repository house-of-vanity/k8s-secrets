FROM rust:1.83-bookworm as builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

COPY . .
RUN touch src/main.rs
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/secret-reader /usr/local/bin/secret-reader
COPY --from=builder /app/templates /templates

EXPOSE 3000

USER 1000

ENTRYPOINT ["/usr/local/bin/secret-reader"]