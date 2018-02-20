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
ARG TAG=latest
ARG REGISTRY=
ARG REPOSITORY=

FROM ${REGISTRY}${REPOSITORY}voltha/voltha-cli:${TAG}
ARG PUB_KEY_FILE=voltha_rsa.pub

RUN mkdir -p /home/voltha/.ssh
RUN echo $PUB_KEY_FILE
COPY ${PUB_KEY_FILE} /home/voltha/.ssh/authorized_keys
RUN chown -R voltha.voltha /home/voltha/.ssh
RUN chmod 700 /home/voltha/.ssh
RUN chmod 600 /home/voltha/.ssh/authorized_keys
