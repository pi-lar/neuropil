#
# neuropil development environment Dockerfile
#
#

FROM debian:bookworm-slim

ARG GITLAB_USER_EMAIL
ARG CI_REPOSITORY_URL

LABEL maintainer="${GITLAB_USER_EMAIL}"

RUN apt-get update && \
        apt-get install -y \
        rsync zip unzip bash curl jq

# Install neuropil build dependencies
RUN apt-get install -y \
        build-essential locate clang clang-tools clang-tidy clang-format git cmake valgrind rustc libssl-dev \
        python3 python3-dev python3-venv python3-pip \
        libxml2-dev libxslt-dev \
        ninja-build libgit2-dev pkg-config automake libffi8 libffi-dev libtool \
        libcriterion-dev libncurses6 libncurses-dev libnanomsg-dev libsodium-dev nanopb \
        graphviz

ENV LANG C.UTF-8

CMD ["bash"]
