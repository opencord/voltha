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

docker run -d --name pbuild -p 9999:9000 portainer/portainer:1.15.2
rm -fr tmp_portainer
mkdir tmp_portainer
docker cp pbuild:/ tmp_portainer

sed -i -e '
s~constant("DOCKER_ENDPOINT","api/docker")~constant("DOCKER_ENDPOINT","docker/api/docker")~
s~constant("CONFIG_ENDPOINT","api/settings")~constant("CONFIG_ENDPOINT","docker/api/settings")~
s~constant("AUTH_ENDPOINT","api/auth")~constant("AUTH_ENDPOINT","docker/api/auth")~
s~constant("USERS_ENDPOINT","api/users")~constant("USERS_ENDPOINT","docker/api/users")~
s~constant("ENDPOINTS_ENDPOINT","api/endpoints")~constant("ENDPOINTS_ENDPOINT","docker/api/endpoints")~
s~constant("TEMPLATES_ENDPOINT","api/templates")~constant("TEMPLATES_ENDPOINT","docker/api/templates")~
' tmp_portainer/js/app.*.js
sed -i -e '
s~href="~href="docker/~
s~href='\''~href='\''docker/~
s~src="~src="docker/~
s~src='\''~src='\''docker/~
s~"images/logo.png"~"docker/images/logo.png"~
' tmp_portainer/index.html

docker build -t ${REGISTRY}${REPOSITORY}voltha-portainer:${TAG} -f docker/Dockerfile.portainer .
rm -fr tmp_portainer
docker stop pbuild
docker rm -f pbuild

