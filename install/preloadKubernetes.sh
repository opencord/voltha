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

uId=`id -u`
vmName="voltha_voltha${uId}"

# Get the VM's ip address
ipAddr=`virsh domifaddr $vmName | tail -n +3 | awk '{ print $4 }' | sed -e 's~/.*~~'`

# Retrieve stable kubespray repo
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i \
	../.vagrant/machines/voltha${uId}/libvirt/private_key vagrant@$ipAddr \
       "git clone --branch v2.5.0 https://github.com/kubernetes-incubator/kubespray.git"

# Setup a new ansible manifest to only download files 
cat <<HERE > download.yml
---
- hosts: k8s-cluster
  any_errors_fatal: "{{ any_errors_fatal | default(true) }}"
  roles:
  - { role: kubespray-defaults}
  - { role: download, tags: download, skip_downloads: false}
HERE

# Copy the manifest over to the voltha instance
scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i \
	../.vagrant/machines/voltha${uId}/libvirt/private_key \
	download.yml vagrant@$ipAddr:kubespray/download.yml

# Run the manifest
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i \
	../.vagrant/machines/voltha${uId}/libvirt/private_key vagrant@$ipAddr \
	"mkdir -p releases && cd kubespray && ANSIBLE_CONFIG=ansible.cfg ansible-playbook -v -u root -i inventory/local/hosts.ini download.yml"

rtrn=$?

echo "Preload return code: $rtrn"

exit $rtrn

