#!/bin/bash

TAG=${TAG:-latest}

rm -fr buildreport
rm -f envoyd
docker run -e "http_proxy=$http_proxy" -e "https_proxy=$https_proxy" -v $(pwd):/src ${REGISTRY}${REPOSITORY}voltha-go-builder:${TAG}
#/build.sh
uid=`id -u`
gid=`id -g`
ls -l buildreport || true
echo "sudo chown -R ${uid}:${gid} buildreport"
sudo chattr -i envoyd buildreport buildreport/*
sudo chown -R ${uid}:${gid} buildreport || true
sudo chown ${uid}:${gid} envoyd || true
