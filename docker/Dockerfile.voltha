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

FROM ${REGISTRY}${REPOSITORY}voltha-base:${TAG}

MAINTAINER Voltha Community <info@opennetworking.org>

# Bundle app source
RUN mkdir /voltha && touch /voltha/__init__.py
ENV PYTHONPATH=/voltha
COPY common /voltha/common
COPY voltha /voltha/voltha
COPY pki /voltha/pki

# Exposing process and default entry point
# EXPOSE 8000
CMD ["python", "voltha/voltha/main.py"]
