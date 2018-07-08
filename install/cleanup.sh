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
git checkout ../voltha/voltha.yml
git checkout ../ofagent/ofagent.yml
git checkout ../netconf/netconf.yml
