#!/bin/bash

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

