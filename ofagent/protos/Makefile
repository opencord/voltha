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

# This makefile is used only to copy relevant *_pb2.py files from Voltha
# to allow ofagent to function properly.


TARGET_PROTO_DIR := $(VOLTHA_BASE)/ofagent/protos
SOURCE_PROTO_DIR := $(VOLTHA_BASE)/voltha/protos
TARGET_GOOGLE_API_DIR := $(TARGET_PROTO_DIR)/third_party/google/api
SOURCE_GOOGLE_API_DIR := $(SOURCE_PROTO_DIR)/third_party/google/api

build: copyfiles

copyfiles:
	rsync -av --include '*/' --exclude='third_party/__init__.py' --include '*.py' --exclude='*' $(SOURCE_PROTO_DIR)/ $(TARGET_PROTO_DIR)
	rsync -av --include '*/' --exclude='third_party/__init__.py' --include '*.py' --include '*.desc' --include '*.proto' --exclude='*' $(SOURCE_GOOGLE_API_DIR)/ $(TARGET_GOOGLE_API_DIR)

clean:
	rm -f $(TARGET_PROTO_DIR)/*_pb2*.py
	rm -f $(TARGET_GOOGLE_API_DIR)/*_pb2*.py
	rm -f $(TARGET_GOOGLE_API_DIR)/*_pb2*.pyc
	rm -f $(TARGET_GOOGLE_API_DIR)/*.proto
	rm -f $(TARGET_GOOGLE_API_DIR)/*.desc
