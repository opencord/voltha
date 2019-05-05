FROM golang:1.10
MAINTAINER Alex Peters <info@alexanderpeters.de>

RUN apt-get update && apt-get install -y apt-transport-https ca-certificates jq curl gnupg2 software-properties-common

RUN curl -fsSL https://download.docker.com/linux/$(. /etc/os-release; echo "$ID")/gpg | apt-key add -
RUN add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/$(. /etc/os-release; echo "$ID") $(lsb_release -cs) stable"

RUN apt-get update && apt-cache policy docker-ce && apt-get install -y upx-ucl docker-ce && apt-get clean

RUN go get github.com/pwaller/goupx \
	&& go get golang.org/x/tools/cmd/cover \
    && go get -u golang.org/x/lint/golint \
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
