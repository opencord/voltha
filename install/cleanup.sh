#!/bin/bash

rm ansible/host_vars/*
rm ansible/roles/voltha/templates/daemon.json
rm -fr volthaInstaller-2/
rm -fr volthaInstaller/
rm ansible/volthainstall.retry
rm key.pem
sed -i -e '/voltha_containers:/,$d' ansible/group_vars/all
git checkout ansible/hosts/voltha
git checkout ansible/hosts/installer
git checkout ../settings.vagrant.yaml

