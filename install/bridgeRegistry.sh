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

# This script is for developers only. It will create tunnels between
# the vm cluster and the installer's registry and between the voltha
# vm and the installer's registry. This allows containers to be
# pushed to the registry and pulled into the cluster allowing to rapidly
# cycle between container development and deployment for testing without
# having to re-build the entire installer and re-deploy the cluster.

uid=`id -u`
iVmName="vInstaller${uid}"
vVmName="voltha_voltha${uid}"
volthaHome=~/cord/incubator/voltha
iIpAddr=`virsh domifaddr $iVmName | tail -n +3 | awk '{ print $4 }' | sed -e 's~/.*~~'`
vIpAddr=`virsh domifaddr $vVmName | tail -n +3 | awk '{ print $4 }' | sed -e 's~/.*~~'`
ssh -f -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i key.pem vinstall@$iIpAddr 'for i in .keys/*; do ssh -f -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ServerAliveInterval=600 -o ServerAliveCountMax=9999 -R 5000:localhost:5000 -i $i voltha@`basename $i` sleep 5999400 ; done'
scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i ../.vagrant/machines/voltha${uid}/libvirt/private_key key.pem vagrant@$vIpAddr:.
ssh -f -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i ../.vagrant/machines/voltha${uid}/libvirt/private_key vagrant@$vIpAddr "ssh -f -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ServerAliveInterval=600 -o ServerAliveCountMax=9999 -L 5000:localhost:5000 -i key.pem vinstall@${iIpAddr} sleep 5999400"
