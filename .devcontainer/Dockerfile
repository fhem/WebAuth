# Managed by FHEM Devcontainer Toolkit.
FROM ghcr.io/fhem/fhem-minimal-docker:5-bookworm

ARG LOCAL_UID=1000
ARG LOCAL_GID=1000
ARG LOCAL_USER=dev

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    less \
    openssh-client \
    procps \
    subversion \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid ${LOCAL_GID} ${LOCAL_USER} \
 && useradd --uid ${LOCAL_UID} --gid ${LOCAL_GID} --create-home --shell /bin/bash ${LOCAL_USER}

ENV HOME=/home/${LOCAL_USER}

RUN cpm install -L /usr/src/app/core --show-build-log-on-failure \
    Perl::Critic \
    Test2::Suite

ENV PERL5LIB=/usr/src/app/core/lib/perl5
