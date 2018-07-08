#!/bin/sh
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

export SRC_DIR="$1"

echo $SRC_DIR

export MAPS=Mgoogle/protobuf/descriptor.proto=github.com/golang/protobuf/protoc-gen-go/descriptor
export INCS="\
    -I $SRC_DIR \
    -I $GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis"

export VOLTHA_PB="\
    $SRC_DIR/adapter.proto \
    $SRC_DIR/device.proto \
    $SRC_DIR/events.proto \
    $SRC_DIR/health.proto \
    $SRC_DIR/logical_device.proto \
    $SRC_DIR/ponsim.proto \
    $SRC_DIR/voltha.proto"

export COMMON_PB="\
    $SRC_DIR/common.proto \
    $SRC_DIR/meta.proto \
    $SRC_DIR/yang_options.proto"

export PONSIM_PB="$SRC_DIR/ponsim_common.proto $SRC_DIR/ponsim_olt.proto"
export SCHEMA_PB="$SRC_DIR/schema.proto"
export IETF_PB="$SRC_DIR/ietf_interfaces.proto"
export OF_PB="$SRC_DIR/openflow_13.proto"
export BAL_PB="$SRC_DIR/bal*.proto"
export BBF_PB="$SRC_DIR/bbf*.proto"
export OMCI_PB="$SRC_DIR/omci*.proto"

export PB_VARS="\
    VOLTHA_PB \
    COMMON_PB \
    PONSIM_PB \
    SCHEMA_PB \
    IETF_PB \
    OF_PB \
    BAL_PB \
    BBF_PB \
    OMCI_PB"

for pb_var in $PB_VARS
do
    pbs="$(eval echo \$$pb_var)"
    echo "Compiling $pbs"
    protoc --go_out=$MAPS,plugins=grpc:$GOPATH/src $INCS $pbs
done
