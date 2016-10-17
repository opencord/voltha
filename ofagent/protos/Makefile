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

# This makefile is used only to copy relevant *_pb2.py files from Voltha
# to allow ofagent to function properly.

PB2_FILES := \
    voltha_pb2.py \
    openflow_13_pb2.py

TARGET_PROTO_DIR := $(VOLTHA_BASE)/ofagent/protos
SOURCE_PROTO_DIR := $(VOLTHA_BASE)/voltha/protos

build: copyfiles

copyfiles:
	rsync -av --include '*/' --include '*.py' --exclude='*' $(SOURCE_PROTO_DIR)/ $(TARGET_PROTO_DIR)

