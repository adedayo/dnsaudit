# Built by GoReleaser, which has already compiled the binary for every target
# platform. Nothing is compiled here: the binary is copied from the build
# context, which GoReleaser lays out as <os>/<arch>/vantage.
#
# The base is distroless static rather than scratch because vantage makes
# HTTPS requests — Certificate Transparency logs, provider address ranges,
# MTA-STS policy files — and those need a CA certificate bundle. On scratch
# every TLS handshake would fail with "certificate signed by unknown
# authority". distroless static carries the bundle and nothing else: no
# shell, no package manager, so there is no interactive attack surface in an
# image whose whole purpose is assessing attack surface.
#
# :nonroot runs as uid 65532. The tool needs no privileges: it makes outbound
# DNS and HTTPS queries and writes only to its cache.
FROM gcr.io/distroless/static:nonroot

ARG TARGETPLATFORM

COPY $TARGETPLATFORM/vantage /usr/bin/vantage

# Provider ranges and Certificate Transparency results are cached here. The
# directory lives inside the container unless a volume is mounted over it, so
# by default a container starts with a cold cache and re-fetches. Mount a
# volume at /home/nonroot/.cache/vantage to persist it between runs.
ENV HOME=/home/nonroot

ENTRYPOINT ["/usr/bin/vantage"]
