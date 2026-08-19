##############################################################################
#
# This file is part of the "Luna OpenSSL for PQC" project.
#
# The " Luna OpenSSL for PQC " project is provided under the MIT license (see the
# following Web site for further details: https://mit-license.org/ ).
#
# Copyright © 2025 Thales Group
#
##############################################################################
#
# Description:
#   This Dockerfile is used to build a container image for the "Luna OpenSSL for PQC" project.

FROM registry.access.redhat.com/ubi8/ubi

#USER root
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Optional local CA cert for TLS-inspecting corporate proxies (e.g. Zscaler).
# Glob pattern is a no-op COPY when the file is absent, so this is safe for
# contributors who don't have zscaler-root-ca.crt locally.
COPY zscaler-root-ca.cr[t] /etc/pki/ca-trust/source/anchors/
RUN \
    update-ca-trust extract

RUN \
    # Upgrade all current packages
    dnf -y update --setopt=tsflags=nodocs --setopt=install_weak_deps=0 --refresh && \
    dnf -y install --setopt=tsflags=nodocs --setopt=install_weak_deps=0 \
    gcc make perl cmake
RUN \
    # Create user and group
    groupadd -g 501 app && \
    useradd -u 1000 -g app -G app -s /bin/bash luna

# Switch to luna user: if execution required to be root, then it should be stated manually, at container run time
USER luna
WORKDIR /home/luna/luna-openssl-provider

ENTRYPOINT []
CMD ["/bin/bash", "-l"]
