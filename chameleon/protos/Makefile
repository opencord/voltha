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

ifeq ($(VOLTHA_BASE)_set,_set)
  $(error To get started, please source the env.sh file from Voltha top level directory)
endif

default: build

PROTO_FILES := $(wildcard *.proto) $(wildcard third_party/google/api/*proto)
PROTO_PB2_FILES := $(foreach f,$(PROTO_FILES),$(subst .proto,_pb2.py,$(f)))
PROTO_DESC_FILES := $(foreach f,$(PROTO_FILES),$(subst .proto,.desc,$(f)))

PROTOC_PREFIX := /usr/local
PROTOC_LIBDIR := $(PROTOC_PREFIX)/lib

build: $(PROTO_PB2_FILES)

%_pb2.py: %.proto Makefile
	@echo "Building protocol buffer artifacts from $<"
	env LD_LIBRARY_PATH=$(PROTOC_LIBDIR) python -m grpc.tools.protoc \
	    -I. \
	    -I./third_party \
	    --python_out=. \
	    --grpc_python_out=. \
	    $<

clean:
	rm -f $(PROTO_PB2_FILES) $(PROTO_DESC_FILES)

