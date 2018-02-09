# Copyright 2017 the original author or authors.
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

FROM centos:7

MAINTAINER Voltha Community <info@opennetworking.org>

# install required packages
RUN ["yum", "install", "-y", "epel-release"]
RUN ["yum", "install", "-y", "git", "make", "libtool", "libxml2-devel", "file", "libxslt-devel", "libssh-devel", "libcurl-devel", "python-pip", "libxml2-python", "openssh-server", "augeas-devel", "readline", "readline-devel", "openssl", "openssl-perl", "openssl-devel", "m2crypto", "which", "unzip", "gcc-c++", "gflags-devel", "gtest-devel", "clang", "c++-devel", "wget"]
RUN ["ssh-keygen", "-A"]
RUN ["pip", "install", "pyang"]
RUN ["yum", "clean", "packages"]
RUN ["yum", "clean", "headers"]

# clone, build and install libnetconf
RUN set -e -x; \
    git clone https://github.com/CESNET/libnetconf.git /usr/src/libnetconf; \
    cd /usr/src/libnetconf; \
    ./configure --enable-tls --prefix='/usr'; \
    make; \
    make install; \
    ln -s /usr/lib/pkgconfig/libnetconf.pc /usr/lib64/pkgconfig/; \
    make clean;

# clone netopeer
RUN set -e -x; \
    git clone https://github.com/CESNET/netopeer.git /usr/src/netopeer;

# build and install netopeer-cli
RUN set -e -x; \
    cd /usr/src/netopeer/cli; \
    ./configure --enable-tls --prefix='/usr'; \
    make; \
    make install; \
    make clean;

# build and install netopeer-server
RUN set -e -x; \
    cd /usr/src/netopeer/server; \
    ./configure --enable-tls --prefix='/usr'; \
    make; \
    make install; \
    cp -v config/datastore.xml /usr/etc/netopeer/cfgnetopeer/datastore.xml; \
    make clean;

# clone, build and install protobuf
RUN set -e -x; \
    git clone -b v3.2.1 https://github.com/google/protobuf.git /usr/src/protobuf; \
    cd /usr/src/protobuf; \
    ./autogen.sh; \
    ./configure; \
    make; \
    make install; \
    ldconfig; \
    make clean;

# Install golang
RUN set -e -x; \
    cd /tmp; \
    wget https://storage.googleapis.com/golang/go1.8.1.linux-amd64.tar.gz; \
    tar -C /usr/local -xzf /tmp/go1.8.1.linux-amd64.tar.gz; \
    rm -f /tmp/go1.8.1.linux-amd64.tar.gz

# Setup necessary environment variables
ENV GOROOT /usr/local/go
ENV PATH $PATH:$GOROOT/bin

RUN ["mkdir", "/usr/local/share/go"]
ENV GOPATH /usr/local/share/go
ENV PATH $PATH:$GOPATH/bin

# Install golang protobuf/grpc libraries
RUN set -e -x; \
    go get -u github.com/golang/protobuf/{proto,protoc-gen-go}; \
    go get -u google.golang.org/grpc; \
    go get -u github.com/hashicorp/consul/api;

# Build and Install the golang Voltha GRPC client layer
COPY netopeer/voltha-grpc-client /usr/src/voltha-grpc-client
RUN set -e -x; \
    mkdir -p /usr/local/share/go/src/github.com/opencord/voltha/netconf; \
    ln -s /usr/src/voltha-grpc-client /usr/local/share/go/src/github.com/opencord/voltha/netconf/translator; \
    cd /usr/src/voltha-grpc-client; \
    go build -buildmode=c-shared -o voltha.so voltha.go; \
    mv voltha.so /usr/lib64; \
    mv voltha.h /usr/include; \
    cp voltha-defs.h /usr/include; \
    rm -f /usr/lib64/libvoltha.so; \
    ln -s /usr/lib64/voltha.so /usr/lib64/libvoltha.so;

# ------------------------------------------------
# Sample transapi implementation
#
# To demonstrate the integration with the netopeer netconf server
#

# Build and Install the golang Voltha model conversion package
COPY netopeer/voltha-netconf-model /usr/src/voltha-netconf-model
RUN set -e -x; \
    cd /usr/src/voltha-netconf-model; \
    go build -buildmode=c-shared -o voltha-netconf-model.so netconf-model.go; \
    mv voltha-netconf-model.so /usr/lib64; \
    mv voltha-netconf-model.h /usr/include; \
    rm -f /usr/lib64/libvoltha-netconf-model.so; \
    ln -s /usr/lib64/voltha-netconf-model.so /usr/lib64/libvoltha-netconf-model.so;

# Build and install the Voltha netconf transapi library
COPY netopeer/voltha-transapi /usr/src/netopeer/voltha-transapi
RUN set -e -x; \
    cd /usr/src/netopeer/voltha-transapi; \
    autoreconf --install; \
    ./configure --prefix='/usr'; \
    make; \
    make install; 

# Finally start the netopeer-server with debugging logs enabled
CMD ["/usr/bin/netopeer-server", "-v", "3"]

# Expose the default netconf port
EXPOSE 830
