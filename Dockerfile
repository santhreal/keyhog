# Pin to bookworm so the builder's glibc matches the bookworm runtime stage.
# Plain `rust:1.89-slim` tracks Debian testing (trixie, glibc 2.39+) and
# produces a binary that fails to load on the bookworm runtime with
# `GLIBC_2.39 not found`.
FROM rust:1.89-slim-bookworm AS builder
WORKDIR /build

# Build-time deps: libssl-dev is required by reqwest's default
# native-tls/OpenSSL transport used by verification and network sources.
# pkg-config locates OpenSSL, and ca-certificates covers Cargo fetches.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        ca-certificates \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --locked --release -p keyhog

FROM debian:bookworm-slim
# Runtime deps: ca-certificates supports HTTPS verification and network
# sources. Git supports history and repository sources.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/keyhog /usr/local/bin/keyhog
COPY --from=builder /build/detectors /usr/share/keyhog/detectors

# Default to a non-root uid to avoid the scanner running as root inside
# containers that mount host volumes read/write.
RUN useradd --system --create-home --uid 1000 keyhog
USER keyhog

ENTRYPOINT ["keyhog"]
CMD ["scan", "--help"]
