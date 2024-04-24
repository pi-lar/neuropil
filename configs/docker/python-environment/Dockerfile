ARG GITLAB_USER_EMAIL
ARG NEUROPIL_BASE_IMAGE

FROM $NEUROPIL_BASE_IMAGE

LABEL maintainer="${GITLAB_USER_EMAIL}"

COPY "build/bindings/python/dist/neuropil-*.zip" neuropil.zip
RUN rm /usr/local/lib/libneuropil.so.* && rm /usr/local/lib/libneuropil.a.* 

RUN ldconfig 
RUN apt-get update && apt-get -y install python3 libffi8 curl python3-pip
RUN pip3 install neuropil.zip && rm neuropil.zip
RUN ldconfig 

CMD ["bash"]
