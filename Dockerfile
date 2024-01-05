FROM rust:1.69-bookworm
ARG http_proxy
ENV http_proxy=$http_proxy
ENV https_proxy=$http_proxy
ENV HTTP_PROXY=$http_proxy
ENV HTTPS_PROXY=$http_proxy
RUN echo Acquire::http::Proxy "${http_proxy}"; > /etc/apt/apt.conf.d/70debconf

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
       eatmydata \
    && eatmydata apt-get -y dist-upgrade \
    && eatmydata apt-get install --no-install-recommends -y \
       build-essential \
       bash \
       ca-certificates \
       clang \
       curl \
       emscripten \
       hunspell \
       libclang-dev \
       libssl-dev \
       llvm \
       pkg-config \
       syslog-ng \
       sudo \
    && eatmydata apt -y autoremove \
    && eatmydata apt clean \
    && rm -rf /var/lib/apt/lists/*

ARG UID
RUN useradd -m -u $UID satoshi
USER satoshi
WORKDIR /home/satoshi

RUN rustup component add clippy-preview \
 && rustup component add rustfmt
RUN rustup target add wasm32-unknown-unknown
RUN rustup target add wasm32-wasi
RUN rustup target add wasm32-unknown-emscripten

