#!/bin/bash

TAG=${TAG:-latest}

rm -fr buildreport
rm -f envoyd
docker run -e "http_proxy=$http_proxy" -e "https_proxy=$https_proxy" -v $(pwd):/src ${REGISTRY}${REPOSITORY}voltha-go-builder:${TAG}
uid=`id -u`
sudo chown -R ${uid} buildreport
sudo chown ${uid} envoyd
