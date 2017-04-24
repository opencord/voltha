#!/bin/bash

docker run --rm -d --name pbuild -p 9999:9000 portainer/portainer
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


docker build -t voltha/portainer -f docker/Dockerfile.portainer .
rm -fr tmp_portainer
docker stop pbuild

