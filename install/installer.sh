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
wd=`pwd`


# Clean up any prior executions
rm -fr .keys
rm -f ansible/hosts/cluster
rm -f ansible/host_vars/*

# Source the configuration information
. install.cfg

# Create the key directory
mkdir .keys

# Create the host list
echo "[cluster]" > ansible/hosts/cluster

# Silence SSH and avoid prompts
rm -f ~/.ssh/config
echo "Host *" > ~/.ssh/config
echo "	StrictHostKeyChecking no" >> ~/.ssh/config
echo "	UserKnownHostsFile /dev/null" >> ~/.ssh/config

sudo cp ~/.ssh/config /root/.ssh/config


for i in $hosts
do
	# Generate the key for the host
	echo -e "${lBlue}Generating the key-pair for communication with host ${yellow}$i${NC}"
	ssh-keygen -f ./$i -t rsa -N ''
	mv $i .keys

	# Generate the pre-configuration script
	echo -e "${lBlue}Creating the pre-configuration script${NC}"
	cat <<HERE > bash_login.sh
#!/bin/bash
	echo "voltha ALL=(ALL) NOPASSWD:ALL" > tmp
	sudo chown root.root tmp
	sudo mv tmp /etc/sudoers.d/voltha
	sudo mkdir /home/voltha
	mkdir voltha_ssh
	ssh-keygen -f ~/voltha_ssh/id_rsa -t rsa -N ''
	sudo mv voltha_ssh /home/voltha/.ssh
HERE
	echo "sudo cat <<HERE > /home/voltha/.ssh/authorized_keys" >> bash_login.sh
	cat $i.pub >> bash_login.sh
	echo "HERE" >> bash_login.sh
	echo "chmod 400 /home/voltha/.ssh/authorized_keys" >> bash_login.sh
	echo "sudo useradd -b /home -d /home/voltha voltha -s /bin/bash" >> bash_login.sh
	echo "sudo chown -R voltha.voltha /home/voltha" >> bash_login.sh
	echo "echo 'voltha:voltha' | sudo chpasswd" >> bash_login.sh
	echo "rm .bash_login" >> bash_login.sh
	echo "logout" >> bash_login.sh
	rm $i.pub
	# Copy the pre-config file to the VM
	echo -e "${lBlue}Transfering pre-configuration script to ${yellow}$i${NC}"
	if [ -d ".test" ]; then
		echo -e "${red}Test mode set!!${lBlue} Using pre-populated ssh key for ${yellow}$i${NC}"
		scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i .test/$i bash_login.sh vagrant@$i:.bash_login
	else
		scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no bash_login.sh vagrant@$i:.bash_login
	fi
	rm bash_login.sh

	# Run the pre-config file on the VM
	echo -e "${lBlue}Running the pre-configuration script on ${yellow}$i${NC}"
	if [ -d ".test" ]; then
		echo -e "${red}Test mode set!!${lBlue} Using pre-populated ssh key for ${yellow}$i${NC}"
		ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i .test/$i vagrant@$i
	else
		ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no vagrant@$i
	fi

	# Configure ansible and ssh for silent operation
	echo -e "${lBlue}Configuring ansible${NC}"
	echo $i >> ansible/hosts/cluster
	echo "ansible_ssh_private_key_file: $wd/.keys/$i" > ansible/host_vars/$i

	# Create the tunnel to the registry to allow pulls from localhost
	echo -e "${lBlue}Creating a secure shell tunnel to the registry for ${yellow}$i${NC}"
	ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i .keys/$i -f voltha@$i -R 5000:localhost:5000 -N
	
done
# Add the dependent software list to the cluster variables
echo -e "${lBlue}Setting up dependent software${NC}"
echo "deb_files:" >> ansible/group_vars/all
for i in deb_files/*.deb
do
echo "  - `basename $i`" >> ansible/group_vars/all
done

# Running ansible
echo -e "${lBlue}Running ansible${NC}"
cp ansible/ansible.cfg .ansible.cfg
sudo ansible-playbook ansible/voltha.yml -i ansible/hosts/cluster

