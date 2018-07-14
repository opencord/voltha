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
#
ARG TAG=latest
ARG REGISTRY=
ARG REPOSITORY=

FROM ${REGISTRY}${REPOSITORY}voltha-protos:${TAG} as protos
FROM ${REGISTRY}${REPOSITORY}voltha-base:${TAG}
MAINTAINER Voltha Community <info@opennetworking.org>

# Bundle app source
RUN mkdir /voltha && touch /voltha/__init__.py
ENV PYTHONPATH=/voltha
COPY common /voltha/common
COPY voltha /voltha/voltha
COPY pki /voltha/pki

# Copy in the generated GRPC proto code
COPY --from=protos /protos/voltha /voltha/voltha/protos
COPY --from=protos /protos/google/api /voltha/voltha/protos/third_party/google/api
COPY --from=protos /protos/asfvolt16_olt /voltha/voltha/adapters/asfvolt16_olt/protos
COPY --from=protos /protos/openolt /voltha/voltha/adapters/openolt/protos
COPY --from=protos /protos/cig_olt /voltha/voltha/protos

# Exposing process and default entry point
# EXPOSE 8000
CMD ["python", "voltha/voltha/main.py"]
