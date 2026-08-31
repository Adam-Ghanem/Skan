FROM debian:12@sha256:6ebd97fa83deb272194a2cf015b3d26a4d538e9ad3a7a79d544c8af5b0a01443

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential debhelper dpkg-dev lintian ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
