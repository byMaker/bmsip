FROM rust:1-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends pulseaudio-utils alsa-utils \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add rustfmt clippy \
    && mkdir -p /cargo /workspace \
    && chown -R 1000:1000 /cargo /workspace /usr/local/cargo

ENV CARGO_HOME=/cargo

WORKDIR /workspace
