#!/bin/bash

rm -f ansible/host_vars/*
rm -f ansible/roles/voltha/templates/daemon.json
rm -fr volthaInstaller-2/
rm -fr volthaInstaller/
rm -f ansible/*.retry
rm -fr .test
rm -fr .tmp.keys
rm -f key.pem
sed -i -e '/voltha_containers:/,$d' ansible/group_vars/all
git checkout ../ansible/roles/docker/templates/daemon.json
git checkout ansible/hosts/voltha
git checkout ansible/hosts/installer
git checkout ../settings.vagrant.yaml
git checkout settings.vagrant.yaml 
git checkout ansible/group_vars/all
git checkout ansible/roles/docker/templates/docker.cfg
git checkout install.cfg
