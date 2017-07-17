#!/bin/bash

rm -fr buildreport
rm -f envoyd
docker run -v $(pwd):/src go-builder
#/build.sh
uid=`id -u`
gid=`id -g`
sudo chown -R ${uid}.${gid} buildreport
sudo chown ${uid}.${gid} envoyd
