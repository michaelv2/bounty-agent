# bounty-sandbox: runs untrusted Foundry tests. See SPEC.md §4.1.
#
# Pins (from the 2026-11-21 security audit; bump only with a fresh audit):
#   - debian:bookworm-slim by digest
#   - Foundry v1.9.0 release tarball, SHA-256 checked here and matching the
#     release's published .sha256 file. Only `forge` is extracted.
#
# The final stage installs no packages (apt would pull unpinned versions). The CA
# bundle is copied from the build stage; only the solc installer needs it.
#
# Hardening is applied at run time by bounty_agent/sandbox/runner.py
# (--network none, --read-only, --cap-drop ALL, no-new-privileges, host uid/gid).
#
# Build:  docker build -t bounty-sandbox:latest sandbox/foundry

ARG DEBIAN=debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

FROM ${DEBIAN} AS fetch-foundry
ARG FOUNDRY_VERSION=v1.9.0
ARG FOUNDRY_SHA256=8d17599b42e3139f1a9c171be3798c4ed8e743ae17b84cc3435e57bf2a51ae99
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/foundry.tgz \
      "https://github.com/foundry-rs/foundry/releases/download/${FOUNDRY_VERSION}/foundry_${FOUNDRY_VERSION}_linux_amd64.tar.gz" \
 && echo "${FOUNDRY_SHA256}  /tmp/foundry.tgz" | sha256sum -c - \
 && mkdir /out && tar -xzf /tmp/foundry.tgz -C /out forge

FROM ${DEBIAN}
COPY --from=fetch-foundry /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=fetch-foundry /out/forge /usr/local/bin/forge
RUN mkdir -p /target
WORKDIR /target
# No ENTRYPOINT: the runner passes a fixed command.
CMD ["forge", "--version"]
