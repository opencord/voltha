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

key="{{ key }}"

lBlue='\033[1;34m'
green='\033[0;32m'
orange='\033[0;33m'
NC='\033[0m'
red='\033[0;31m'
yellow='\033[1;33m'
dGrey='\033[1;30m'
lGrey='\033[1;37m'
lCyan='\033[1;36m'


if grep voltha /etc/passwd 2>&1 > /dev/null; then
	echo -e "${yellow}WARNING:${lBlue}a ${yellow}voltha ${lBlue} user exists on the system!!"
	echo -e "This account will be re-used by the installer. If you encounter any problems"
	echo -e "please review the account setup to ensure it is correctly set up to run voltha."
fi

if [  -d /home/voltha ]; then
	echo -e "${lBlue}A directory ${yellow}/home/voltha ${green}exists ${red}NOT ${lBlue}creating...${NC}"
else
	sudo mkdir /home/voltha
fi

if [ -f /home/voltha/.ssh/id_rsa ]; then
	echo -e "${lBlue}A ssh key file ${yellow}/home/voltha/ssh/id_rsa ${green}exists ${red}NOT ${lBlue}creating...${NC}"
else
	mkdir voltha_ssh
	ssh-keygen -f ~/voltha_ssh/id_rsa -t rsa -N ''
	sudo mv voltha_ssh /home/voltha/.ssh
fi

if [ -f /etc/sudoers.d/voltha ]; then
	echo -e "${lBlue}A sudoers file ${yellow}/etc/sudoers.d/voltha ${green}exists ${red}NOT ${lBlue}creating...${NC}"
else
	echo "voltha ALL=(ALL) NOPASSWD:ALL" > tmp
	sudo chown root.root tmp
	sudo mv tmp /etc/sudoers.d/voltha
fi

if sudo test -f /home/voltha/.ssh/authorized_keys ; then
	sudo chmod ugo+w /home/voltha/.ssh/authorized_keys
	echo $key > key.tmp
	sudo cat key.tmp >> /home/voltha/.ssh/authorized_keys
	rm key.tmp
	sudo chmod 400 /home/voltha/.ssh/authorized_keys

else
	sudo echo $key > /home/voltha/.ssh/authorized_keys
	sudo chmod 400 /home/voltha/.ssh/authorized_keys
fi

if grep voltha /etc/passwd 2>&1 > /dev/null; then
	echo -e "${lBlue}A ${yellow}voltha ${lBlue} user account ${green}exists ${red}NOT ${lBlue}creating...${NC}"
	sudo chown voltha.`id -gn voltha` /home/voltha/.ssh/authorized_keys
else
	sudo useradd -b /home -d /home/voltha voltha -s /bin/bash
	echo 'voltha:voltha' | sudo chpasswd
	sudo chown -R voltha.voltha /home/voltha
fi

rm .bash_login
logout

