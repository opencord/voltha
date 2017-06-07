#!/bin/bash

baseImage="Ubuntu1604LTS"
iVmName="vInstaller"
iVmNetwork="default"
shutdownTimeout=5
ipTimeout=20

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
# Update the XML file with the VM information
echo -e "${lBlue}Defining the  ${lCyan}$iVmName${lBlue} virtual machine${NC}"
cat vmTemplate.xml | sed -e "s/{{ VMName }}/$iVmName/g" | sed -e "s/{{ VMNetwork }}/$iVmNetwork/g" > tmp.xml

# Copy the vm image to the default storage pool
echo -e "${lBlue}Creating the storage for the ${lCyan}$iVmName${lBlue} virtual machine${NC}"
# Copy the vm image to the installer directory
virsh pool-create-as installer --type dir --target `pwd`
virsh vol-create-from default ${iVmName}_volume.xml $iVmName.qcow2 --inputpool installer
virsh pool-destroy installer

# Create the VM using the updated xml file and the uploaded image
virsh define tmp.xml

rm tmp.xml

# Start the VMm, if it's already running just ignore the error
echo -e "${lBlue}Starting the ${lCyan}$iVmName${lBlue} virtual machine${NC}"
virsh start $iVmName > /dev/null 2>&1

# Get the VM's IP address
ctr=0
ipAddr=""
while [ -z "$ipAddr" ];
do
	echo -e "${lBlue}Waiting for the VM's IP address${NC}"
	ipAddr=`virsh domifaddr $iVmName | tail -n +3 | awk '{ print $4 }' | sed -e 's~/.*~~'`
	sleep 3
	if [ $ctr -eq $ipTimeout ]; then
		echo -e "${red}Tired of waiting, please adjust the ipTimeout if the VM is slow to start${NC}"
		exit
	fi
	ctr=`expr $ctr + 1`
done

# Log into the vm
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i key.pem vinstall@$ipAddr
