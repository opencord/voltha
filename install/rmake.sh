#!/bin/bash

# This script is for developers only. It will sync the local filesystem
# to the voltha vm and then rebuild each of the targets specified on the
# command line.

cont=$1
uid=`id -u`
iVmName="vInstaller${uid}"
vVmName="voltha_voltha${uid}"
volthaHome=~/cord/incubator/voltha
iIpAddr=`virsh domifaddr $iVmName | tail -n +3 | awk '{ print $4 }' | sed -e 's~/.*~~'`
vIpAddr=`virsh domifaddr $vVmName | tail -n +3 | awk '{ print $4 }' | sed -e 's~/.*~~'`

# TODO: Validate the command line and print a help message

pushd ~/cord/incubator/voltha
vagrant rsync
popd
pushd ~/cord/incubator/voltha/install
# Build each of the specified targets
for i in $@
do
	ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i ../.vagrant/machines/voltha${uid}/libvirt/private_key vagrant@$vIpAddr "cd /cord/incubator/voltha && source env.sh && make $i"
done
popd
