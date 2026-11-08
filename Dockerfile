# syntax=docker/dockerfile:1
#
# Runtime image for slaplog.
#
# It copies a binary built on AlmaLinux 9 (glibc 2.34 baseline) into a small
# Debian 12 runtime and runs as a non-root user.  The binary is produced by
# `packaging/build-local.sh` (local) or by the release workflow (CI), and is
# expected at dist/slaplog-linux-<TARGETARCH>.
#
# Build locally:
#   packaging/build-local.sh --container
# or:
#   podman build --build-arg TARGETARCH=amd64 --build-arg VERSION=5.4.0 -t slaplog .
#
# Multi-arch (CI):
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     --build-arg VERSION=5.4.0 -t ghcr.io/zx97/slaplog:5.4.0 .
FROM debian:12-slim

ARG TARGETARCH=amd64
ARG VERSION=dev

LABEL org.opencontainers.image.title="slaplog" \
      org.opencontainers.image.description="(Open)LDAP log analyzer" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/zx97/slaplog" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libpcre2-8-0 zlib1g libbz2-1.0 liblzma5 ca-certificates passwd \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 slaplog \
 && useradd --uid 10001 --gid slaplog --no-create-home \
        --shell /usr/sbin/nologin slaplog

COPY dist/slaplog-linux-${TARGETARCH} /usr/bin/slaplog
RUN chmod 0755 /usr/bin/slaplog && chown root:root /usr/bin/slaplog

USER 10001:10001
ENTRYPOINT ["/usr/bin/slaplog"]
