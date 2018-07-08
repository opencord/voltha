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

baseImage="Ubuntu1604LTS"
iVmName="vInstaller"
iVmNetwork="default"
shutdownTimeout=5
ipTimeout=10
installerArchive="installer.tar.bz2"
installerPart="installer.part"

lBlue='\033[1;34m'
green='\033[0;32m'
orange='\033[0;33m'
NC='\033[0m'
red='\033[0;31m'
yellow='\033[1;33m'
dGrey='\033[1;30m'
lGrey='\033[1;37m'
lCyan='\033[1;36m'

wd=`pwd`

# Check if the tar file is available.
echo -e "${lBlue}Checking for the installer archive ${lCyan}$installerArchive${NC}"

if [ ! -f $installerArchive ]; then
	# The installer file ins't there, check for parts to re-assemble
	echo -e "${lBlue}Checking for the installer archive parts ${lCyan}$installerPart*${NC}"
	fList=`ls ${installerPart}*`
	if [ -z "$fList" ]; then
		echo -e "${red} Could not find installer archive or installer archive parts, ABORTING.${NC}"
		exit
	else
		# All is well, concatenate the files together to create the installer archive
		echo -e "${lBlue}Creating the installer archive ${lCyan}$installerArchive${NC}"
		cat $fList > installer.tar.bz2
		rm -fr $fList
	fi
fi

# Extract the installer files and bootstrap the installer
echo -e "${lBlue}Extracting the content of the installer archive ${lCyan}$installerArchive${NC}"
tar xjf $installerArchive
echo -e "${lBlue}Starting the installer${NC}"
chmod u+x BootstrapInstaller.sh
./BootstrapInstaller.sh "$@"
