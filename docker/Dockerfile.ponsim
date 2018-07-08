# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -------------
# Build stage

FROM golang:1.9.2-alpine AS build-env

# Install required packages
RUN apk add --no-cache wget git libpcap-dev make build-base protobuf protobuf-dev

# Prepare directory structure
RUN ["mkdir", "-p", "/src/pki", "/src/protos"]
RUN ["mkdir", "-p", "$GOPATH/src", "$GOPATH/pkg", "$GOPATH/bin"]
RUN ["mkdir", "-p", "$GOPATH/src/github.com/opencord/voltha/protos/go"]

# Copy files
ADD ponsim/v2 $GOPATH/src/github.com/opencord/voltha/ponsim/v2
ADD ponsim/v2 /src
ADD pki /src/pki

# Copy required proto files
# ... VOLTHA protos
ADD voltha/protos/*.proto /src/protos/
# ... BAL protos
ADD voltha/adapters/asfvolt16_olt/protos/*.proto /src/protos/
# ... PONSIM protos
ADD ponsim/v2/protos/*.proto /src/protos/

# Install golang protobuf and pcap support
RUN go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
RUN go get -u github.com/golang/protobuf/protoc-gen-go
RUN go get -u github.com/google/gopacket/pcap

# Compile protobuf files
RUN sh /src/scripts/build_protos.sh /src/protos

# Build ponsim
RUN cd /src && go get -d ./... && go build -o ponsim

# -------------
# Final stage

FROM alpine

# Install required packages
RUN apk add --no-cache libpcap-dev
WORKDIR /app

# Copy required files
COPY --from=build-env /src/ponsim /app/
COPY --from=build-env /src/pki /app/pki

ENV VOLTHA_BASE /app
