#
# neuropil development enviroment Dockerfile
#
#

FROM ubuntu:22.04

ARG GITLAB_USER_EMAIL
ARG CI_REPOSITORY_URL

LABEL maintainer="${GITLAB_USER_EMAIL}"


RUN apt-get update && \
    apt-get install -y \
        lsb-release wget software-properties-common \
        rsync zip unzip bash curl jq
        
RUN bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"

# Install neuropil build dependencies
RUN apt-get install -y \
        build-essential locate clang clang-tools clang-tidy clang-format git cmake valgrind rustc libssl-dev \
        python3 python3-dev python3-pip python3-venv \
        libxml2-dev libxslt-dev \
        ninja-build libgit2-dev pkg-config automake libtool \
        libcriterion-dev libncurses5 libncurses5-dev libnanomsg-dev libsodium-dev nanopb \
        graphviz

ENV LANG C.UTF-8

CMD ["bash"]
