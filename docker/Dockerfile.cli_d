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

RUN apt-get update && apt-get install -y openssh-server

# Bundle app source
RUN mkdir /cli && touch /cli/__init__.py
ENV PYTHONPATH=/cli
COPY common /cli/common
COPY cli /cli/cli
COPY voltha /cli/voltha
COPY --from=protos /protos/voltha /cli/voltha/protos
COPY --from=protos /protos/google/api /cli/voltha/protos/third_party/google/api
COPY --from=protos /protos/asfvolt16_olt /cli/voltha/adapters/asfvolt16_olt/protos
RUN useradd -b /home -d /home/voltha voltha -s /bin/bash
RUN mkdir /home/voltha
RUN chown voltha.voltha /home/voltha
RUN echo "voltha:admin" | chpasswd

RUN mkdir /var/run/sshd
RUN echo 'root:screencast' | chpasswd
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile

EXPOSE 22

# Exposing process and default entry point
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

CMD ["/cli/cli/setup.sh"]
