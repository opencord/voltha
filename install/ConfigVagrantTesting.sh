#!/bin/bash

baseImage="Ubuntu1604LTS"
iVmName="Ubuntu1604LTS-1"
iVmNetwork="vagrant-libvirt"
shutdownTimeout=5
ipTimeout=10

lBlue='\033[1;34m'
green='\033[0;32m'
orange='\033[0;33m'
NC='\033[0m'
red='\033[0;31m'
yellow='\033[1;33m'
dGrey='\033[1;30m'
lGrey='\033[1;37m'
lCyan='\033[1;36m'

# Shut down the domain in case it's running.
#echo -e "${lBlue}Shut down the ${lCyan}$iVmName${lBlue} VM if running${NC}"
#ctr=0
#vStat=`virsh list | grep $iVmName`
#while [ ! -z "$vStat" ];
#do
#	virsh shutdown $iVmName
#	echo "Waiting for $iVmName to shut down"
#	sleep 2
#	vStat=`virsh list | grep $iVmName`
#	ctr=`expr $ctr + 1`
#	if [ $ctr -eq $shutdownTimeout ]; then
#		echo -e "${red}Tired of waiting, forcing the VM off${NC}"
#		virsh destroy $iVmName
#		vStat=`virsh list | grep $iVmName`
#	fi
#done


# Delete the VM and ignore any errors should they occur
#echo -e "${lBlue}Undefining the ${lCyan}$iVmName${lBlue} domain${NC}"
#virsh undefine $iVmName

# Remove the associated volume
#echo -e "${lBlue}Removing the ${lCyan}$iVmName.qcow2${lBlue} volume${NC}"
#virsh vol-delete "${iVmName}.qcow2" default

# Clone the base vanilla ubuntu install
#echo -e "${lBlue}Cloning the ${lCyan}$baseImage.qcow2${lBlue} to ${lCyan}$iVmName.qcow2${NC}"
#virsh vol-clone "${baseImage}.qcow2" "${iVmName}.qcow2" default

# Create the xml file and define the VM for virsh
#echo -e "${lBlue}Defining the  ${lCyan}$iVmName${lBlue} virtual machine${NC}"
#cat vmTemplate.xml | sed -e "s/{{VMName}}/$iVmName/g" | sed -e "s/{{VMNetwork}}/$iVmNetwork/g" > tmp.xml

#virsh define tmp.xml

#rm tmp.xml

# Start the VMm, if it's already running just ignore the error
#echo -e "${lBlue}Starting the ${lCyan}$iVmName${lBlue} virtual machine${NC}"
#virsh start $iVmName > /dev/null 2>&1


# Configure ansible's key for communicating with the VMs... Testing only, this will
# be taken care of by the installer in the future.
for i in install_ha-serv1 install_ha-serv2 install_ha-serv3
do
	ipAddr=`virsh domifaddr $i | tail -n +3 | awk '{ print $4 }' | sed -e 's~/.*~~'`
	m=`echo $i | sed -e 's/install_//'`
	echo "ansible_ssh_private_key_file: .vagrant/machines/$m/libvirt/private_key" > ansible/host_vars/$ipAddr
done

exit

echo -e "${lBlue}Generating the key-pair for communication with the VM${NC}"
ssh-keygen -f ./key -t rsa -N ''

mv key key.pem

# Clone BashLogin.sh and add the public key to it for later use.
echo -e "${lBlue}Creating the pre-configuration script${NC}"
cp BashLogin.sh bash_login.sh
echo "cat <<HERE > .ssh/authorized_keys" >> bash_login.sh
cat key.pub >> bash_login.sh
echo "HERE" >> bash_login.sh
echo "chmod 400 .ssh/authorized_keys" >> bash_login.sh
echo "rm .bash_login" >> bash_login.sh
echo "logout" >> bash_login.sh
rm key.pub



# Get the VM's IP address
ctr=0
ipAddr=""
while [ -z "$ipAddr" ];
do
	echo -e "${lBlue}Waiting for the VM's IP address${NC}"
	ipAddr=`virsh domifaddr $iVmName | tail -n +3 | awk '{ print $4 }' | sed -e 's~/.*~~'`
	sleep 2
	if [ $ctr -eq $ipTimeout ]; then
		echo -e "${red}Tired of waiting, please adjust the ipTimeout if the VM is slow to start${NC}"
		exit
	fi
	ctr=`expr $ctr + 1`
done

echo -e "${lBlue}The IP address is: ${lCyan}$ipAddr${NC}"

# Copy the pre-config file to the VM
echo -e "${lBlue}Transfering pre-configuration script to the VM${NC}"
scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no bash_login.sh vinstall@$ipAddr:.bash_login

rm bash_login.sh

# Run the pre-config file on the VM
echo -e "${lBlue}Running the pre-configuration script on the VM${NC}"
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no vinstall@$ipAddr 

# Make sure the VM is up-to-date
echo -e "${lBlue}Ensure that the VM is up-to-date${NC}"
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i key.pem vinstall@$ipAddr sudo apt-get update 
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i key.pem vinstall@$ipAddr sudo apt-get -y upgrade 

# Create the docker.cfg file in the ansible tree using the VMs IP address
echo 'DOCKER_OPTS="$DOCKER_OPTS --insecure-registry '$ipAddr':5000 -H tcp://0.0.0.0:2375 -H unix:///var/run/docker.sock --registry-mirror=http://'$ipAddr':5001"' > ansible/roles/docker/templates/docker.cfg

# Install ansible on the vm, it'll be used both here and for the install
echo -e "${lBlue}Installing ansible on the VM${NC}"
#ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i key.pem vinstall@$ipAddr sudo apt-get install software-properties-common
#ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i key.pem vinstall@$ipAddr sudo apt-add-repository ppa:ansible/ansible
#ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i key.pem vinstall@$ipAddr sudo apt-get update
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i key.pem vinstall@$ipAddr sudo apt-get -y install ansible

# Copy the ansible files to the VM
echo -e "${lBlue}Transferring the ansible directory to the VM${NC}"
scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i key.pem -r ansible vinstall@$ipAddr:ansible

# Get the GPG key for docker otherwise ansible calls break
echo -e "${lBlue}Get the GPG key for docker to allow ansible playbooks to run successfully${NC}"
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i key.pem vinstall@$ipAddr "sudo apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D"

# Bootstrap ansible
echo -e "${lBlue}Bootstrap ansible${NC}"
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i key.pem vinstall@$ipAddr ansible/scripts/bootstrap_ansible.sh

# Run the ansible script to initialize the installer environment
echo -e "${lBlue}Run the nsible playbook for the installer${NC}"
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i key.pem vinstall@$ipAddr sudo PYTHONUNBUFFERED=1 ansible-playbook /home/vinstall/ansible/volthainstall.yml -c local
