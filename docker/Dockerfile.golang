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

FROM golang:1.9.2
MAINTAINER Voltha Community <info@opennetworking.org>

RUN apt-get update && apt-get install -y apt-transport-https ca-certificates jq curl gnupg2 software-properties-common

RUN curl -fsSL https://download.docker.com/linux/$(. /etc/os-release; echo "$ID")/gpg | apt-key add -
RUN add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/$(. /etc/os-release; echo "$ID") $(lsb_release -cs) stable"

RUN apt-get update && apt-cache policy docker-ce && apt-get install -y upx-ucl docker-ce && apt-get clean

RUN go get github.com/pwaller/goupx \
	&& go get golang.org/x/tools/cmd/cover \
    && go get -u github.com/golang/lint/golint \
    && go get github.com/kisielk/errcheck \
    && go get github.com/cespare/prettybench \
    && go get github.com/uber/go-torch

# Install dependency management tools
# gpm
RUN wget https://raw.githubusercontent.com/pote/gpm/v1.3.2/bin/gpm -O /usr/local/bin/gpm && \
  chmod +x /usr/local/bin/gpm

# glide
ENV glide_version=v0.12.3
RUN mkdir -p bin ; \
    curl -L  https://github.com/Masterminds/glide/releases/download/${glide_version}/glide-${glide_version}-linux-amd64.tar.gz | \
    tar -xz -C bin ; \
  	mv bin/linux-amd64/glide bin/glide; \
    rm -rf bin/linux-amd64


ARG GITHUB_TOKEN
RUN echo "machine github.com login $GITHUB_TOKEN" >/root/.netrc

COPY build_environment.sh /
COPY build.sh /

VOLUME /src
WORKDIR /src

ENV GORACE="halt_on_error=1"

ENTRYPOINT ["/build.sh"]
