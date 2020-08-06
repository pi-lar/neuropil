#
# neuropil development enviroment Dockerfile
#
#

FROM ubuntu:18.04

ARG GITLAB_USER_EMAIL
RUN echo "GITLAB_USER_EMAIL=${GITLAB_USER_EMAIL}"
ARG CI_REPOSITORY_URL
RUN echo "CI_REPOSITORY_URL=${CI_REPOSITORY_URL}"
ARG CI_COMMIT_SHA
RUN echo "CI_COMMIT_SHA=${CI_COMMIT_SHA}"

ENV LIBSODIUM_VERSION 1.0.18

LABEL maintainer="${GITLAB_USER_EMAIL}"

WORKDIR /root

# Install some tools: clang, build tools, unzip, etc
RUN \
    apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install curl build-essential unzip locate clang python3 python3-setuptools git virtualenv cmake bash && \
    apt-get -y install python3-dev libxml2-dev libxslt-dev && \
    apt-get -y install ninja-build libgit2-dev pkg-config

# Download and install libsodium
# https://download.libsodium.org/doc/
RUN \
    mkdir -p /tmpbuild/libsodium && \
    cd /tmpbuild/libsodium && \
    curl -L https://download.libsodium.org/libsodium/releases/libsodium-${LIBSODIUM_VERSION}.tar.gz -o libsodium-${LIBSODIUM_VERSION}.tar.gz && \
    tar xfvz libsodium-${LIBSODIUM_VERSION}.tar.gz && \
    cd /tmpbuild/libsodium/libsodium-${LIBSODIUM_VERSION}/ && \
    ./configure && \
    make && make check && \
    make install && \
    mv src/libsodium /usr/local/ && \
    rm -Rf /tmpbuild/ && \
    ldconfig

# install dependencies for neuropil examples
RUN \
    apt-get -y install libncurses5-dev libncursesw5-dev libsqlite3-dev

# prepare neuropil development
RUN \
    git clone "${CI_REPOSITORY_URL}" && \
    cd neuropil  && \
    git reset --hard "${CI_COMMIT_SHA}" && \
    ./do ensure_dependencies

CMD ["bash"]
