#!/bin/bash +x
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

SRC_DIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VOLTHA_DIR="$SRC_DIR/../../.."

echo "Run Robot Framework TEST. Log: $1"
cd $VOLTHA_DIR
source env.sh
robot -d $1 -v LOG_DIR:$1/voltha_test_results ./tests/atests/robot/voltha_automated_test_suite.robot
