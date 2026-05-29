# Pin to bookworm so the builder's glibc matches the bookworm runtime stage.
# Plain `rust:1.89-slim` tracks Debian testing (trixie, glibc 2.39+) and
# produces a binary that fails to load on the bookworm runtime with
# `GLIBC_2.39 not found`.
FROM rust:1.89-slim-bookworm AS builder
WORKDIR /build

# Build-time deps: libhyperscan-dev links the `simd` feature against libhs;
# libssl-dev is required by reqwest's default (native-tls/openssl) TLS, used
# by the verify/web/github/s3 backends - without it openssl-sys fails to
# build. pkg-config locates both. ca-certificates covers cargo fetches.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libhyperscan-dev \
        pkg-config \
        ca-certificates \
        libssl-dev \
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
