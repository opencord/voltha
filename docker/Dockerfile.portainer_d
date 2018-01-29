# Copyright 2018 the original author or authors.
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

FROM ${REGISTRY}portainer/portainer:1.15.2 as base

FROM ${REGISTRY}alpine:3.6 as work
COPY --from=base / /work
RUN find /work  -print

RUN sed -i \
-e 's~constant("DOCKER_ENDPOINT","api/docker")~constant("DOCKER_ENDPOINT","docker/api/docker")~' \
-e 's~constant("CONFIG_ENDPOINT","api/settings")~constant("CONFIG_ENDPOINT","docker/api/settings")~' \
-e 's~constant("AUTH_ENDPOINT","api/auth")~constant("AUTH_ENDPOINT","docker/api/auth")~' \
-e 's~constant("USERS_ENDPOINT","api/users")~constant("USERS_ENDPOINT","docker/api/users")~' \
-e 's~constant("ENDPOINTS_ENDPOINT","api/endpoints")~constant("ENDPOINTS_ENDPOINT","docker/api/endpoints")~' \
-e 's~constant("TEMPLATES_ENDPOINT","api/templates")~constant("TEMPLATES_ENDPOINT","docker/api/templates")~' \
/work/public/js/app.*.js

RUN sed -i \
-e 's~href="~href="docker/~' \
-e 's~href='\''~href='\''docker/~' \
-e 's~src="~src="docker/~' \
-e 's~src='\''~src='\''docker/~' \
-e 's~"images/logo.png"~"docker/images/logo.png"~' \
/work/public/index.html

FROM centurylink/ca-certs
MAINTAINER Voltha Community <info@opennetworking.org>

COPY --from=work /work /

VOLUME /data

WORKDIR /

EXPOSE 9000

ENTRYPOINT ["/portainer"]
