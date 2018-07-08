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

# This script is for developers only. It will move a container from
# the voltha VM to the registry and from the registry to each of the
# machines in the cluster. The script is pretty dumb so it will fail
# if a service is running that needs the container so it's best to
# ensure that this isn't the case.

cont=$1
uid=`id -u`
iVmName="vInstaller${uid}"
vVmName="voltha_voltha${uid}"
volthaHome=~/cord/incubator/voltha
iIpAddr=`virsh domifaddr $iVmName | tail -n +3 | awk '{ print $4 }' | sed -e 's~/.*~~'`
vIpAddr=`virsh domifaddr $vVmName | tail -n +3 | awk '{ print $4 }' | sed -e 's~/.*~~'`
pushd ~/cord/incubator/voltha/install
# Delete the registry push tag and create a new one just to be sure it points to the right container
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i ../.vagrant/machines/voltha${uid}/libvirt/private_key vagrant@$vIpAddr "docker rmi localhost:5000/${1}"
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i ../.vagrant/machines/voltha${uid}/libvirt/private_key vagrant@$vIpAddr "docker tag ${1} localhost:5000/${1}"

# Push the container to the registry
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i ../.vagrant/machines/voltha${uid}/libvirt/private_key vagrant@$vIpAddr "docker push localhost:5000/${1}"

scp -r -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i key.pem vinstall@$iIpAddr:.keys .tmp.keys

for i in .tmp.keys/*
do
	ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i $i voltha@`basename $i` docker rmi -f ${1}
	ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i $i voltha@`basename $i` docker rmi -f localhost:5000/${1}
	ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i $i voltha@`basename $i` docker pull localhost:5000/${1}
	ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i $i voltha@`basename $i` docker tag localhost:5000/${1} ${1}
done

#ssh -f -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i key.pem vinstall@$iIpAddr 'for i in .keys/*; do ssh -f -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ServerAliveInterval=600 -o ServerAliveCountMax=9999  -i $i voltha@`basename $i` docker rmi -f '${1}' && docker rmi -f localhost:5000/'${1}' && docker pull localhost:5000/'${1}' && docker tag localhost:5000/'${1}' '${1}'; done'
#scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i ../.vagrant/machines/voltha${uid}/libvirt/private_key key.pem vagrant@$vIpAddr:.
#ssh -f -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i ../.vagrant/machines/voltha${uid}/libvirt/private_key vagrant@$vIpAddr "ssh -f -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ServerAliveInterval=600 -o ServerAliveCountMax=9999 -L 5000:localhost:5000 -i key.pem vinstall@${iIpAddr} sleep 5999400"
popd
