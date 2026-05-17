FROM rust:1.94-bookworm AS chef
RUN cargo install cargo-chef
WORKDIR /build

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin fakecloud

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --fix-missing \
    ca-certificates \
    curl \
    git \
    wget \
    jq \
    openssh-client \
    less \
    libcap2 \
    libsystemd0 \
    && apt-get upgrade -y libcap2 libsystemd0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/fakecloud /usr/local/bin/
EXPOSE 4566
ENTRYPOINT ["fakecloud"]
