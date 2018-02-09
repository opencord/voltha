# Copyright 2016 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
ARG TAG=latest
ARG REGISTRY=
ARG REPOSITORY=

FROM ${REGISTRY}${REPOSITORY}voltha-protos:${TAG} as protos
FROM ${REGISTRY}${REPOSITORY}voltha-base:${TAG}

MAINTAINER Voltha Community <info@opennetworking.org>

# Install protoc version 3.0.0; this is not yet the supported
# version on xenial, so we need to "backport" it
RUN apt-get update && \
    apt-get install -y zlib1g-dev wget && \
    wget http://ftp.us.debian.org/debian/pool/main/p/protobuf/libprotoc10_3.0.0-9_amd64.deb && \
    wget http://ftp.us.debian.org/debian/pool/main/p/protobuf/libprotobuf-lite10_3.0.0-9_amd64.deb && \
    wget http://ftp.us.debian.org/debian/pool/main/p/protobuf/libprotobuf-dev_3.0.0-9_amd64.deb && \
    wget http://ftp.us.debian.org/debian/pool/main/p/protobuf/libprotobuf10_3.0.0-9_amd64.deb && \
    wget http://ftp.us.debian.org/debian/pool/main/p/protobuf/protobuf-compiler_3.0.0-9_amd64.deb && \
    dpkg -i *.deb && \
    protoc --version && \
    rm -f *.deb

# Bundle app source
RUN mkdir -p /ofagent/ofagent/protos/third_party/google/api  && \
	touch	/ofagent/__init__.py \
		/ofagent/ofagent/protos/third_party/google/__init__.py \
		/ofagent/ofagent/protos/third_party/google/api/__init__.py
ENV PYTHONPATH=/ofagent
COPY common /ofagent/common
COPY ofagent /ofagent/ofagent
COPY pki /ofagent/pki
COPY --from=protos /protos/voltha /ofagent/ofagent/protos
COPY --from=protos /protos/google/api /ofagent/ofagent/protos/third_party/google/api

ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# Exposing process and default entry point
CMD ["dumb-init", "python", "ofagent/ofagent/main.py"]
