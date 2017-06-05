#!/bin/bash

vmName="voltha_voltha"

# Voltha directory
cd ..

# Destroy the VM if it's running
vagrant destroy voltha

# Bring up the VM.
vagrant up voltha

# Get the VM's ip address
ipAddr=`virsh domifaddr $vmName | tail -n +3 | awk '{ print $4 }' | sed -e 's~/.*~~'`

# Run all the build commands
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i .vagrant/machines/voltha/libvirt/private_key vagrant@$ipAddr "cd /cord/incubator/voltha && . env.sh && make fetch && make"
