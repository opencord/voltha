#
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
#

# Makefile to build all protobuf and gRPC related artifacts

ifeq ($(VOLTHA_BASE)_set,_set)
  $(error To get started, please source the env.sh file from Voltha top level directory)
endif

PROTO_FILES := $(wildcard *.proto) $(wildcard third_party/google/api/*proto)
PROTO_PB2_FILES := $(foreach f,$(PROTO_FILES),$(subst .proto,_pb2.py,$(f)))
PROTO_DESC_FILES := $(foreach f,$(PROTO_FILES),$(subst .proto,.desc,$(f)))

PROTOC_PREFIX := /usr/local
PROTOC_LIBDIR := $(PROTOC_PREFIX)/lib

build: copyprotos $(PROTO_PB2_FILES) copypb2files

%_pb2.py: %.proto Makefile
	@echo "Building protocol buffer artifacts from $<"
	env LD_LIBRARY_PATH=$(PROTOC_LIBDIR) python -m grpc.tools.protoc \
	    -I. \
	    -I./third_party \
	    --python_out=. \
	    --grpc_python_out=. \
	    $<

TARGET_PROTO_DIR := $(VOLTHA_BASE)/netconf/protos
SOURCE_PROTO_DIR := $(VOLTHA_BASE)/voltha/protos

TARGET_YANG_OPTION_DIR := $(VOLTHA_BASE)/netconf/protoc_plugins
YANG_OPTION_FILE := yang_options_pb2.py
YANG_PROTO_FILE := yang_options.proto
SCHEMA_PROTO_FILE := schema.proto

copyprotos:
	cp $(SOURCE_PROTO_DIR)/$(SCHEMA_PROTO_FILE) $(TARGET_PROTO_DIR)
	cp $(SOURCE_PROTO_DIR)/$(YANG_PROTO_FILE) $(TARGET_PROTO_DIR)

copypb2files:
	rsync -av --include '*/' --exclude='third_party/__init__.py' --include '*.py' --exclude='*' $(SOURCE_PROTO_DIR)/ $(TARGET_PROTO_DIR)
	cp $(SOURCE_PROTO_DIR)/$(YANG_OPTION_FILE) $(TARGET_YANG_OPTION_DIR)

clean:
	rm -f $(PROTO_PB2_FILES) $(PROTO_DESC_FILES)
	rm -f $(TARGET_YANG_OPTION_DIR)/$(YANG_OPTION_FILE)
	rm -f $(TARGET_PROTO_DIR)/*.py
	rm -f $(TARGET_PROTO_DIR)/*.pyc
	rm -f $(TARGET_PROTO_DIR)/*.proto


