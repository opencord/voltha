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

SRC_DIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"
BUILD_DIR="$SRC_DIR/../build"

cd ${BUILD_DIR}
if [[ $# -ne 2 ]]
  then
    echo "Wrong number of arguments supplied"
    exit 1
fi
if [[ -z "${1}" || -z "${2}" ]]
  then
    echo "Empty argument supplied"
    exit 1
fi
if [[ "${1}" == "clear" ]]
  then
    sudo make reset-kubeadm
elif [[ "${1}" == "start" ]]
  then
    sudo service docker restart
    sudo make -f Makefile ${2}
elif [[ "${1}" == "stop" ]]
  then
    pods=$( /usr/bin/kubectl get pods --all-namespaces 2>&1 | grep -c -e refused -e resource )
    if  [[ ${pods} -eq 0 ]]
      then
        sudo make teardown-charts
    fi
fi
exit 0
