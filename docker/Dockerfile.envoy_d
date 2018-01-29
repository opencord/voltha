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
ARG HTTP_PROXY=
ARG HTTPS_PROXY=

FROM grpc/python as protos
COPY voltha/protos/*.proto /voltha/protos/
COPY voltha/protos/third_party/google/api/*.proto /voltha/protos/third_party/google/api/
#RUN protoc -I/voltha/protos -I/voltha/protos/third_party --include_imports --include_source_info --descriptor_set_out=/proto.pb /voltha/protos/*.proto
RUN python -m grpc.tools.protoc -I/voltha/protos -I/voltha/protos/third_party --include_imports --include_source_info --descriptor_set_out=/proto.pb /voltha/protos/*.proto

FROM ${REGISTRY}${REPOSITORY}voltha-go-builder:${TAG} as build
ENV http_proxy ${HTTP_PROXY}
ENV https_proxy ${HTTPS_PROXY}

COPY envoy/go/envoyd/*.go /src/
RUN mkdir /output
RUN OUTPUT=/ /build.sh
RUN ls /output

FROM lyft/envoy:29361deae91575a1d46c7a21e913f19e75622ebe

RUN apt-get update && apt-get -q install -y curl
COPY envoy/front-proxy /envoy
COPY --from=protos /proto.pb /envoy/
COPY pki /envoy/
COPY --from=build /envoyd /usr/local/bin/envoyd

CMD /usr/local/bin/envoy -c /envoy/front-proxy/voltha-grpc-proxy.json
