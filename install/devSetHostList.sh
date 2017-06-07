#!/bin/bash

# This script is for development use. It copies all of the
# required files and directories to the installer VM to
# allow changes to be made without having to rebuild the
# VM and it's registry which is time consuming.

# usage devCopyTiInstaller.sh <ip-address>


sed -i -e '/^#/!d' install.cfg
rm -fr .test
mkdir .test
hosts=""
for i in `virsh list | awk '{print $2}' | grep ha-serv`
do
	ipAddr=`virsh domifaddr $i | tail -n +3 | head -n 1 | awk '{print $4}' | sed -e 's~/.*~~'`
	hosts="$hosts $ipAddr"
	hName=`echo $i | sed -e 's/install_//'`
	cat .vagrant/machines/$hName/libvirt/private_key > .test/$ipAddr
done
echo "hosts=\"$hosts\"" >> install.cfg
echo 'iUser="vagrant"' >> install.cfg
