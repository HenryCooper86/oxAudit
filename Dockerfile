# oxAudit command line — the no-install path for any machine with a
# container runtime.
#
#   docker run --rm -v "$PWD:/workspace" ghcr.io/henrycooper86/oxaudit \
#     scan /workspace --format sarif --fail-on high
#
# Released as a multi-architecture image (linux/amd64 + linux/arm64) by the
# release workflow; each architecture is built natively on its own runner,
# never under emulation. The release notes pin the image digest, and the
# image is cosign-signed with the same keyless identity as the release
# binaries — see SECURITY.md for verification.

# --- build -------------------------------------------------------------------
#
# The builder carries the same system libraries the CI verify job installs
# before building the workspace: the Tauri runtime code the CLI links through
# compiles only when webkit2gtk's development headers are present, even
# though the CLI binary itself never opens a window. Plain `cargo build`
# (no `custom-protocol` feature) needs no built frontend, which is the same
# reason the release pipeline's CLI-only jobs need no npm step.
# Both base images are pinned and swappable in one place; the ARGs live in
# the global scope (before any FROM) so both FROM lines can see them.
ARG RUST_IMAGE=rust:1.97.1-bookworm
ARG RUNTIME_IMAGE=debian:12-slim
FROM ${RUST_IMAGE} AS build

ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_TERM_COLOR=always

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential file libayatana-appindicator3-dev librsvg2-dev \
      libssl-dev libwebkit2gtk-4.1-dev libxdo-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# rust-toolchain.toml pins the compiler; Cargo.lock pins the dependency
# graph (--locked below refuses to drift from either).
COPY rust-toolchain.toml ./
COPY src-tauri/ ./src-tauri/
# The library embeds the committed benchmark corpus at compile time
# (quality.rs include_dir!s ../benchmarks/corpus), so it must be in the
# context even though the image never ships it.
COPY benchmarks/ ./benchmarks/

RUN cargo build --manifest-path src-tauri/Cargo.toml --release --locked --bin oxaudit-cli

# --- runtime -----------------------------------------------------------------
#
# Kept deliberately small: the engine is the binary. The linked CLI needs
# only libc/libm/libgcc (verified with ldd); libssl3 rides along as
# insurance for CLI code paths that could link OpenSSL via the keyring
# chain, git backs the history scanner and Git evidence, and
# ca-certificates backs every advisory, CVE, and registry lookup the CLI
# can make.
FROM ${RUNTIME_IMAGE}

ARG VCS_REF
ARG VERSION

LABEL org.opencontainers.image.title="oxAudit CLI" \
      org.opencontainers.image.description="Supply-chain security scanner: source, secrets, dependencies, binaries, images" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/HenryCooper86/oxAudit"

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      git \
      libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /build/src-tauri/target/release/oxaudit-cli /usr/local/bin/oxaudit-cli

# Scans run unprivileged. Mount the project to scan at /workspace; the
# writable home keeps temp caches (advisory receipts, enrichment cache)
# working without --db.
RUN useradd --create-home --uid 1000 scanner
USER scanner
WORKDIR /workspace
ENTRYPOINT ["oxaudit-cli"]
