#!/bin/bash

TAG=${TAG:-latest}

rm -fr buildreport
rm -f envoyd
docker run -e "http_proxy=$http_proxy" -e "https_proxy=$https_proxy" -v $(pwd):/src ${REGISTRY}${REPOSITORY}voltha-go-builder:${TAG}
#/build.sh
uid=`id -u`
gid=`id -g`
sudo chown -R ${uid}:${gid} buildreport
sudo chown ${uid}:${gid} envoyd
