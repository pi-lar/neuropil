#
# neuropil development enviroment Dockerfile
#
#

FROM ubuntu:18.04

ARG GITLAB_USER_EMAIL
ARG CI_REPOSITORY_URL

LABEL maintainer="${GITLAB_USER_EMAIL}"


# Install neuropil build dependencies
RUN apt-get update && \
    apt-get install -y \
        rsync zip unzip bash wget curl jq\
        build-essential locate clang clang-tools git cmake valgrind \
        python3 python3-dev python3-pip python3-venv \
        libxml2-dev libxslt-dev \
        ninja-build libgit2-dev pkg-config automake libtool \
        libncurses5-dev libncursesw5-dev libsqlite3-dev

ENV LANG C.UTF-8

CMD ["bash"]
