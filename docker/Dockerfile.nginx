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
# Handle pre-requisites
RUN apt-get update && apt-get -y install nginx-full && apt-get -y install wget
# Download the consul-template software
RUN wget https://releases.hashicorp.com/consul-template/0.18.2/consul-template_0.18.2_linux_amd64.tgz -O - | tar xzf - -C /usr/bin 
#
RUN mkdir -p /nginx_config
COPY nginx_config /nginx_config
# Exposing process and default entry point
ENTRYPOINT ["/nginx_config/start_service.sh"]

# CMD ["/nginx_config/start_service.sh"]
