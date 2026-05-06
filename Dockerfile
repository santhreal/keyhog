FROM rust:1.89-slim AS builder
WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/keyhog /usr/local/bin/keyhog
COPY --from=builder /build/detectors /opt/keyhog/detectors
ENV KEYHOG_DETECTORS=/opt/keyhog/detectors
ENTRYPOINT ["keyhog"]
CMD ["scan", "--help"]
