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

default: third_party build

PROTO_FILES := $(wildcard *.proto)
PROTO_GOOGLE_API := $(wildcard third_party/google/api/*.proto)
PROTO_ALL_FILES := $(PROTO_FILES) $(PROTO_GOOGLE_API)
PROTO_PB2_FILES := $(foreach f,$(PROTO_FILES),$(subst .proto,_pb2.py,$(f)))
PROTO_PB2_GOOGLE_API := $(foreach f,$(PROTO_GOOGLE_API),$(subst .proto,_pb2.py,$(f)))
PROTO_All_PB2_C_FILES := $(foreach f,$(PROTO_ALL_FILES),$(subst .proto,_pb2.pyc,$(f)))
PROTO_ALL_PB2_GPRC_FILES := $(foreach f,$(PROTO_ALL_FILES),$(subst .proto,_pb2_grpc.py,$(f)))
PROTO_ALL_DESC_FILES := $(foreach f,$(PROTO_ALL_FILES),$(subst .proto,.desc,$(f)))

# Google API needs to be built from within the third party directory
#
third_party: google_api
google_api: protoc
	@echo "Building protocol buffer artifacts from third_party google api"
	docker run --rm -ti -v $(shell pwd)/third_party:/protos opencord/voltha-protoc \
                /usr/bin/python -m grpc.tools.protoc \
                        -I/protos \
			--python_out=/protos \
                        --grpc_python_out=/protos \
                        --descriptor_set_out=/protos/google/api/annotations.desc \
                        --include_imports \
                        --include_source_info \
			/protos/google/api/annotations.proto /protos/google/api/http.proto

build: protoc $(PROTO_PB2_FILES)

%_pb2.py: %.proto Makefile
	@echo "Building protocol buffer artifacts from $<"
	docker run --rm -ti \
                -v $(shell pwd):/protos \
		opencord/voltha-protoc \
		/usr/bin/python -m grpc.tools.protoc \
			-I/protos \
			-I/protos/third_party \
			--python_out=/protos \
			--grpc_python_out=/protos \
			--descriptor_set_out=/protos/$(basename $<).desc \
			--include_imports \
			--include_source_info \
			/protos/$<

clean:
	rm -f $(PROTO_PB2_FILES) \
		$(PROTO_ALL_DESC_FILES) \
		$(PROTO_ALL_PB2_GPRC_FILES) \
		$(PROTO_All_PB2_C_FILES) \
		$(PROTO_PB2_GOOGLE_API)

protoc:
	docker build --rm --force-rm -t opencord/voltha-protoc -f ../../docker/Dockerfile.protoc ../.. 
