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

# This was required before as logging was different in production vs development. The
# logging decision was made at compile time.
# By using the docker logging option (docker swarm mode only) in the deployment
# files, now the logging decision is made at deployment time, hence the same voltha,
# netconf and ofagent images can be used both in development and production.
#cp voltha/voltha.production.yml voltha/voltha.yml
#cp ofagent/ofagent.production.yml ofagent/ofagent.yml
#cp netconf/netconf.production.yml netconf/netconf.yml

# Destroy the VM if it's running
vagrant destroy voltha${uId}

# Bring up the VM.
vagrant up voltha${uId}

# Get the VM's ip address
ipAddr=`virsh domifaddr $vmName | tail -n +3 | awk '{ print $4 }' | sed -e 's~/.*~~'`


# Run all the build commands
if [ $# -eq 1 -a "$1" == "test" ]; then
	ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i \
		.vagrant/machines/voltha${uId}/libvirt/private_key vagrant@$ipAddr \
		"cd /cord/incubator/voltha && . env.sh && make fetch && make build"
	rtrn=$?
else
	ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i \
		.vagrant/machines/voltha${uId}/libvirt/private_key vagrant@$ipAddr \
		"cd /cord/incubator/voltha && . env.sh && make fetch && make production"
	rtrn=$?
fi

echo "Build return code: $rtrn"

exit $rtrn

