# Reproducible build/test/experiment environment for Q-EVM.
# Used because the host (Windows 11 with Smart App Control) blocks unsigned
# locally built executables; Linux containers are unaffected.
FROM rust:1.100.0-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ENV CARGO_TARGET_DIR=/target \
    CARGO_TERM_COLOR=never
WORKDIR /work
