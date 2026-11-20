FROM rust:1-bookworm

RUN rustup component add rustfmt clippy \
    && mkdir -p /cargo /workspace \
    && chown -R 1000:1000 /cargo /workspace /usr/local/cargo

ENV CARGO_HOME=/cargo

WORKDIR /workspace

