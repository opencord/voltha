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
#RUN mkdir /cli && touch /cli/__init__.py
#ENV PYTHONPATH=/cli
#COPY common /cli/common
#COPY cli /cli/cli
#COPY voltha /cli/voltha
RUN useradd -b /home -d /home/tools tools -s /bin/bash
RUN mkdir /home/tools
COPY docker/config/bashrc /home/tools/.bashrc
COPY install/install_consul_cli.sh /home/tools
RUN chown -R tools.tools /home/tools
RUN echo "tools:tools" | chpasswd
RUN apt-get update && apt-get -y upgrade && apt-get -y install openssh-server kafkacat iputils-ping vim manpages iproute2 net-tools moreutils
RUN mkdir /var/run/sshd
RUN chmod +x /home/tools/install_consul_cli.sh
RUN /home/tools/install_consul_cli.sh
RUN rm /home/tools/install_consul_cli.sh
RUN echo 'root:screencast' | chpasswd
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile

EXPOSE 22

# Exposing process and default entry point
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

CMD ["/usr/sbin/sshd", "-D"]
