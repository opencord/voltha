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

default: copyfiles

TARGET_PROTO_DIR := $(VOLTHA_BASE)/netconf/protos
SOURCE_PROTO_DIR := $(VOLTHA_BASE)/voltha/protos

copyfiles:
	rsync -av --include '*/' --exclude='third_party/__init__.py' --include '*.py' --exclude='*' $(SOURCE_PROTO_DIR)/ $(TARGET_PROTO_DIR)


clean:
	rm -f $(PROTO_PB2_FILES) $(PROTO_DESC_FILES)

