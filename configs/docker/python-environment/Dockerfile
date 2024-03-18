ARG GITLAB_USER_EMAIL
ARG NEUROPIL_BASE_IMAGE

FROM $NEUROPIL_BASE_IMAGE

LABEL maintainer="${GITLAB_USER_EMAIL}"

COPY "build/bindings/python/dist/neuropil-*.zip" neuropil.zip
RUN rm /usr/local/lib/libneuropil.so.* && rm /usr/local/lib/libneuropil.a.* && ldconfig && apk update \
    && apk add python3 libffi && \
    pip3 install neuropil.zip && \
    rm neuropil.zip

CMD ["bash"]
