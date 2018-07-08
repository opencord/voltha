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
