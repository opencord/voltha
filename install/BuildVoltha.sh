#!/bin/bash

uId=`id -u`
vmName="voltha_voltha${uId}"

# Voltha directory
cd ..

# Rename voltha for multi-user support
sed -i -e '/server_name/s/.*/server_name: "voltha'${uId}'"/' settings.vagrant.yaml
# Build voltha in test mode
if [ $# -eq 1 -a "$1" == "test" ]; then
	sed -i -e '/test_mode/s/.*/test_mode: "true"/' settings.vagrant.yaml
fi

# Destroy the VM if it's running
vagrant destroy voltha${uId}

# Bring up the VM.
vagrant up voltha${uId}

# Get the VM's ip address
ipAddr=`virsh domifaddr $vmName | tail -n +3 | awk '{ print $4 }' | sed -e 's~/.*~~'`


# Run all the build commands
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i .vagrant/machines/voltha${uId}/libvirt/private_key vagrant@$ipAddr "cd /cord/incubator/voltha && . env.sh && make fetch && make build"
