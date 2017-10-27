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

PROTO_FILES := $(wildcard *.proto) $(wildcard $(VOLTHA_BASE)/voltha/protos/third_party/google/api/*proto)
PROTO_PB2_FILES := $(foreach f,$(PROTO_FILES),$(subst .proto,_pb2.py,$(f)))
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

build: $(PROTOC) protos

protos: $(PROTO_PB2_FILES)

%_pb2.py: %.proto Makefile
	@echo "Building protocol buffer artifacts from $<"
	env LD_LIBRARY_PATH=$(PROTOC_LIBDIR) python -m grpc.tools.protoc \
	    -I. \
	    -I$(VOLTHA_BASE)/voltha/protos/third_party \
	    --python_out=. \
	    --grpc_python_out=. \
	    --descriptor_set_out=$(basename $<).desc \
	    --include_imports \
	    --include_source_info \
	    $<

clean:
	rm -f $(PROTO_PB2_FILES) $(PROTO_DESC_FILES)

$(PROTOC):
	@echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	@echo "It looks like you don't have protocol buffer tools installed."
	@echo "To install the protocol buffer toolchain, you can run:"
	@echo "    make install-protoc"
	@echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

install-protoc: $(PROTOC)
	@echo "Downloading and installing protocol buffer support."
	@echo "Installation will require sodo priviledges"
	@echo "This will take a few minutes."
	mkdir -p $(PROTOC_BUILD_TMP_DIR)
	@echo "We ask for sudo credentials now so we can install at the end"; \
	sudo echo "Thanks"; \
	    cd $(PROTOC_BUILD_TMP_DIR); \
	    wget $(PROTOC_DOWNLOAD_URI); \
	    tar xzvf $(PROTOC_TARBALL); \
	    cd $(PROTOC_DIR); \
	    ./configure --prefix=$(PROTOC_PREFIX); \
	    make; \
	    sudo make install

uninstall-protoc:
	cd $(PROTOC_BUILD_TMP_DIR)/$(PROTOC_DIR); \
	    sudo make uninstall

