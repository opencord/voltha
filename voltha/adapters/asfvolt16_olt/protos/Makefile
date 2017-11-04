#
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
#

# Makefile to build all protobuf and gRPC related artifacts

default: build

PROTO_FILES := $(wildcard *.proto) $(wildcard $(VOLTHA_BASE)/voltha/protos/third_party/google/api/*proto)
PROTO_PB2_FILES := $(foreach f,$(PROTO_FILES),$(subst .proto,_pb2.py,$(f)))
PROTO_PB2_GPRC_FILES := $(foreach f,$(PROTO_FILES),$(subst .proto,_pb2_grpc.py,$(f)))
PROTO_DESC_FILES := $(foreach f,$(PROTO_FILES),$(subst .proto,.desc,$(f)))

PROTOC_PREFIX := /usr/local
PROTOC_LIBDIR := $(PROTOC_PREFIX)/lib

PROTOC := $(PROTOC_PREFIX)/bin/protoc

PROTOC_VERSION := "3.3.0"
PROTOC_DOWNLOAD_PREFIX := "https://github.com/google/protobuf/releases/download"
PROTOC_DIR := protobuf-$(PROTOC_VERSION)
PROTOC_TARBALL := protobuf-python-$(PROTOC_VERSION).tar.gz
PROTOC_DOWNLOAD_URI := $(PROTOC_DOWNLOAD_PREFIX)/v$(PROTOC_VERSION)/$(PROTOC_TARBALL)
PROTOC_BUILD_TMP_DIR := "/tmp/protobuf-build-$(shell uname -s | tr '[:upper:]' '[:lower:]')"

build: $(PROTOC)
	docker run -ti -v $(shell pwd):/bal-protos -w /bal-protos opencord/voltha-protos make -f Makefile.docker

clean:
	rm -f $(PROTO_PB2_FILES) $(PROTO_DESC_FILES) $(PROTO_PB2_GPRC_FILES)

