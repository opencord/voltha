#!/bin/bash
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

TAG=${TAG:-latest}

rm -fr buildreport
rm -f envoyd
docker run -e "http_proxy=$http_proxy" -e "https_proxy=$https_proxy" -v $(pwd):/src ${REGISTRY}${REPOSITORY}voltha-go-builder:${TAG}
uid=`id -u`
sudo chown -R ${uid} buildreport
sudo chown ${uid} envoyd
