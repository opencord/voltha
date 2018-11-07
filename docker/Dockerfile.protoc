# Copyright 2018 the original author or authors.
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

ARG REGISTRY=
ARG PROTOC_PREFIX=/usr/local
ARG ROTOC_LIBDIR=${PROTOC_PREFIX}/lib
ARG PROTOC=${PROTOC_PREFIX}/bin/protoc
ARG PROTOC_VERSION=3.3.0

FROM ${REGISTRY}debian:stretch-slim
MAINTAINER Voltha Community <info@opennetworking.org>

ENV PROTOC_PREFIX=/usr/local
ENV ROTOC_LIBDIR=${PROTOC_PREFIX}/lib
ENV PROTOC=${PROTOC_PREFIX}/bin/protoc
ENV PROTOC_VERSION=3.3.0
ENV PROTOC_DOWNLOAD_PREFIX=https://github.com/google/protobuf/releases/download
ENV PROTOC_DIR=protobuf-${PROTOC_VERSION}
ENV PROTOC_TARBALL=protobuf-python-${PROTOC_VERSION}.tar.gz
ENV PROTOC_DOWNLOAD_URI=${PROTOC_DOWNLOAD_PREFIX}/v${PROTOC_VERSION}/${PROTOC_TARBALL}

RUN apt-get update -y && apt-get install -y wget build-essential python-dev python-pip
RUN pip install grpcio-tools==1.16.0
WORKDIR /build
RUN wget -q --no-check-certificate ${PROTOC_DOWNLOAD_URI}
RUN tar --strip-components=1 -zxf ${PROTOC_TARBALL}
RUN ./configure --prefix=${PROTOC_PREFIX}
RUN make install
