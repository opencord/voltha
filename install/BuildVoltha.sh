#!/bin/bash

uId=`id -u`
vmName="voltha_voltha${uId}"

# Voltha directory
cd ..

# Blow away the settings file, we're going to set all the settings below
rm -f settings.vagrant.yaml

# Rename voltha for multi-user support
echo "---" > settings.vagrant.yaml
echo "# The name to use for the server" >> settings.vagrant.yaml
echo 'server_name: "voltha'${uId}'"' >> settings.vagrant.yaml
# Make sure that we're using KVM and not virtualbox
echo '# Use KVM as the VM provider' >> settings.vagrant.yaml
echo 'vProvider: "KVM"' >> settings.vagrant.yaml
echo '# Use virtualbox as the VM provider' >> settings.vagrant.yaml
echo '#vProvider: "virtualbox"' >> settings.vagrant.yaml
# Build voltha in the specified mode if any
if [ $# -eq 1 -a "$1" == "test" ]; then
	echo '# This determines if test mode is active' >> settings.vagrant.yaml
	echo 'testMode: "true"' >> settings.vagrant.yaml
	echo '# This determines if installer mode is active' >> settings.vagrant.yaml
	echo 'installMode: "false"' >> settings.vagrant.yaml
elif [ $# -eq 1 -a "$1" == "install" ]; then
	echo '# This determines if installer mode is active' >> settings.vagrant.yaml
	echo 'installMode: "true"' >> settings.vagrant.yaml
	echo '# This determines if test mode is active' >> settings.vagrant.yaml
	echo 'testMode: "false"' >> settings.vagrant.yaml
else
	echo '# This determines if installer mode is active' >> settings.vagrant.yaml
	echo 'installMode: "false"' >> settings.vagrant.yaml
	echo '# This determines if test mode is active' >> settings.vagrant.yaml
	echo 'testMode: "false"' >> settings.vagrant.yaml
fi

# Destroy the VM if it's running
vagrant destroy voltha${uId}

# Bring up the VM.
vagrant up voltha${uId}

# Get the VM's ip address
ipAddr=`virsh domifaddr $vmName | tail -n +3 | awk '{ print $4 }' | sed -e 's~/.*~~'`


# Run all the build commands
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i .vagrant/machines/voltha${uId}/libvirt/private_key vagrant@$ipAddr "cd /cord/incubator/voltha && . env.sh && make fetch && make production" | tee voltha_build.tmp

rtrn=$#

if [ $rtrn -ne 0 ]; then
	rm -f voltha_build.tmp
	exit 1
fi

egrep 'Makefile:[0-9]+: recipe for target .* failed' voltha_build.tmp

rtrn=$#
rm -f voltha_build.tmp
if [ $rtrn -eq 0 ]; then
	# An error occured, notify the caller
	exit 1
fi
