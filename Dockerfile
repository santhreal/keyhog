FROM rust:1.89-slim AS builder
WORKDIR /build

# Build-time deps for the default `simd` feature: libhyperscan-dev links
# against libhs at link time; pkg-config finds it. ca-certificates is
# needed for any cargo registry fetches that happen during the build.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libhyperscan-dev \
        pkg-config \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --release -p keyhog

FROM debian:bookworm-slim
# Runtime deps: libhyperscan5 is the shared library the release binary
# dlopens; ca-certificates is needed for verifier HTTPS; git is needed
# for `keyhog scan --git-history` and the git Source backend.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        libhyperscan5 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/keyhog /usr/local/bin/keyhog
COPY --from=builder /build/detectors /opt/keyhog/detectors
ENV KEYHOG_DETECTORS=/opt/keyhog/detectors

# Default to a non-root uid to avoid the scanner running as root inside
# containers that mount host volumes read/write.
RUN useradd --system --create-home --uid 1000 keyhog
USER keyhog

ENTRYPOINT ["keyhog"]
CMD ["scan", "--help"]
