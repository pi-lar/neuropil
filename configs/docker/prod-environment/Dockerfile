
#
# neuropil production environment Dockerfile
#
#

FROM debian:bookworm-slim

ARG GITLAB_USER_EMAIL

LABEL maintainer="${GITLAB_USER_EMAIL}"

COPY ./neuropil/bin /usr/local/bin
COPY ./neuropil/lib /usr/local/lib
COPY ./neuropil/include /usr/local/include

RUN apt-get update && apt-get install -y libsodium23 libncurses5 && ldconfig
