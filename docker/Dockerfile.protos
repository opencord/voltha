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
ARG REPOSITORY=
ARG TAG=latest

FROM ${REGISTRY}${REPOSITORY}voltha-protoc:${TAG} as builder
MAINTAINER Voltha Community <info@opennetworking.org>

COPY voltha/protos/third_party/google/api/*.proto /protos/google/api/
COPY docker/config/Makefile.protos /protos/google/api/Makefile.protos
WORKDIR /protos
RUN make -f google/api/Makefile.protos google_api
RUN touch /protos/google/__init__.py /protos/google/api/__init__.py

COPY voltha/protos/*.proto /protos/voltha/
COPY docker/config/Makefile.protos /protos/voltha/Makefile.protos
WORKDIR /protos/voltha
RUN make -f Makefile.protos build

COPY voltha/adapters/asfvolt16_olt/protos/*.proto /protos/asfvolt16_olt/
COPY docker/config/Makefile.protos /protos/asfvolt16_olt/Makefile.protos
WORKDIR /protos/asfvolt16_olt
RUN make -f Makefile.protos build

COPY voltha/protos/tech_profile.proto /protos/openolt/
COPY voltha/adapters/openolt/protos/*.proto /protos/openolt/
COPY docker/config/Makefile.protos /protos/openolt/Makefile.protos
WORKDIR /protos/openolt
RUN make -f Makefile.protos build

COPY voltha/adapters/cig_olt/protos/*.proto /protos/cig_olt/
COPY voltha/adapters/cig_olt/protos/Makefile.protos /protos/cig_olt/Makefile.protos
WORKDIR /protos/cig_olt
RUN make -f Makefile.protos build

# Copy the files to a scrach based container to minimize its size
FROM ${REGISTRY}scratch
COPY --from=builder /protos/ /protos/
