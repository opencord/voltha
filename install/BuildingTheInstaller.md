# Running the installer
***
**++Table of contents++**

[TOC]
***
## Bare Metal Setup
**Note:** *If you've already prepared the bare metal machine and have the voltha tree downloaded from haing followed the document ``Building a vOLT-HA Virtual Machine  Using Vagrant on QEMU/KVM`` then skip to [Running the Installer](#Building-the-installer).

Start with an installation of Ubuntu16.04LTS on a bare metal server that is capable of virtualization. How to determine this is beyond the scope of this document. When installing the image ensure that both "OpenSSH server" and "Virtualization Machine Host" are chosen in addition to the default "standard system utilities". Once the installation is complete, login to the box and type ``virsh list``. If this doesnt work then you'll need to troubleshoot the installation. If it works, then proceed to the next section.

##Create the base ubuntu/xenial box
  Though there are some flavors of ubuntu boxes available but they usually have additional features installed or missing so it's best to just create the image from the ubuntu installation iso image.
  
  ```
  
  voltha> wget http://releases.ubuntu.com/xenial/ubuntu-16.04.2-server-i386.iso
  voltha> echo "virt-install -n Ubuntu16.04 -r 1024 --vcpus=2 --disk size=50 -c ubuntu-16.04.2-server-amd64.iso --accelerate --network network=default,model=virtio --connect=qemu:///system --vnc --noautoconsole -v" > Ubuntu16.04Vm
  voltha> . Ubuntu16.04Vm
  voltha> virt-manager
```
Once the virt manager opens, open the console of the Ubuntu16.04 VM and follow the installation process.
When promprompted use the hostname ``voltha``. Also when prompted you should create one user ``Vagrant Vagrant`` and use the offered up userid of ``vagrant``. When prompted for the password of the vagrant user, use ``vagrant``. When asked if a weak password should be used, select yes. Don't encrypt the home directory. Select the OpenSSH server when prompted for packages to install.
Once the installation is complete, run the VM and log in as vagrant password vagrant and install the default vagrant key (this can be done one of two ways, through virt-manager and the console or by uing ssh from the hypervisor host, the virt-manager method is shown below):
```
vagrant@voltha$ mkdir -p /home/vagrant/.ssh
vagrant@voltha$ chmod 0700 /home/vagrant/.ssh
vagrant@voltha$ wget --no-check-certificate \
    https://raw.github.com/mitchellh/vagrant/master/keys/vagrant.pub \
    -O /home/vagrant/.ssh/authorized_keys
vagrant@voltha$ chmod 0600 /home/vagrant/.ssh/authorized_keys
vagrant@voltha$ chown -R vagrant /home/vagrant/.ssh
```
Also create a .ssh directory for the root user:
```
vagrant@voltha$ sudo mkdir /root/.ssh
```
Add a vagrant file to /etc/sudoers.d/vagrant with the following:
```
vagrant@voltha$ echo "vagrant ALL=(ALL) NOPASSWD:ALL" > tmp.sudo
vagrant@voltha$ sudo mv tmp.sudo /etc/sudoers.d/vagrant
```

## Install and configure vagrant
Vagrant comes with the Ubuntu 16.04 but it doesn't work with kvm. Downloading and installing the version from hashicorp solves the problem.
```
voltha> wget https://releases.hashicorp.com/vagrant/1.9.5/vagrant_1.9.3_x86_64.deb
voltha> sudo dpkg -i vagrant_1.9.3_x86_64.deb
voltha> vagrant plugin install vagrant-cachier
voltha> sudo apt-get install libvirt-dev
voltha> vagrant plugin install vagrant-libvirt
```
## Create the default vagrant box

When doing this, be careful that you're not in a directory where a Vagrantfile already exists or you'll trash it. It is recommended that a temporary directory is created to perform these actions and then removed once the new box has been added to vagrant.
```
voltha> cp /var/lib/libvirt/images/Ubuntu16.04.qcow2 box.img
voltha> echo '{
"provider"     : "libvirt",
"format"       : "qcow2",
"virtual_size" : 50
}' > metadata.json
voltha> cat <<HERE > Vagrantfile
Vagrant.configure("2") do |config|
     config.vm.provider :libvirt do |libvirt|
     libvirt.driver = "kvm"
     libvirt.host = 'localhost'
     libvirt.uri = 'qemu:///system'
     end
config.vm.define "new" do |custombox|
     custombox.vm.box = "custombox"       
     custombox.vm.provider :libvirt do |test|
     test.memory = 1024
     test.cpus = 1
     end
     end
end
HERE
voltha> tar czvf ubuntu1604.box ./metadata.json ./Vagrantfile ./box.img
voltha> vagrant box add ubuntu1604.box
```
##Download the voltha tree
The voltha tree contains the Vagrant files required to build a multitude of VMs required to both run, test, and also to deploy voltha. The easiest approach is to download the entire tree rather than trying to extract the specific ``Vagrantfile(s)`` required.
```
voltha> sudo apt-get install repo
voltha> mkdir cord
voltha>  sudo ln -s /cord `pwd`/cord
voltha>  cd cord
voltha>  repo init -u https://gerrit.opencord.org/manifest -g voltha
voltha>  repo sync
```

## Run vagrant to Create a Voltha VM
First create the voltah VM using vagrant.
```
voltha> vagrant up
```
Finally, if required, log into the vm using vagrant.
```
voltha> vagrant ssh
```
## Building the Installer
There are 2 different ways to build the installer in production and in test mode.
### Building the installer in test mode
Test mode is useful for testers and developers. The installer build script will also launch 3 vagrant VMs that will be install targets and configure the installer to use them without having to supply passwords for each. This speeds up the subsequent install/test cycle.

To build the installer in test mode go to the installer directory
``cd /cord/incubator/voltha/install``
then type
``./CreateInstaller.sh test``.

This will take a while so doing something else in the mean-time is recommended.

### Running the installer in test mode
Once the creation has completed determine the ip address of the VM with the following virs command:
``virsh domifaddr Ubuntu16.04LTS-1``
using the ip address provided log into the installer using
``ssh -i key.pem vinstall@<ip-address-from-above>``

Finally, start the installer.
``./installer.sh``
In test mode it'll just launch with no prompts and install voltha on the 3 VMs created at the same time that the installer was created (ha-serv1, ha-serv2, and ha-serv3). This step takes quite a while since 3 different voltha installs are taking place, one for each of the 3 VMs in the cluster.

Once the installation completes, determine the ip-address of one of the cluster VMs.
``virsh domifaddr ha-serv1``
You can use ``ha-serv2`` or ``ha-serv3`` in place of ``ha-serv1`` above. Log into the VM
``ssh voltah@<ip-address-from-above>``
Once logged into the voltha instance follow the usual procedure to start voltha and validate that it's operating correctly.

### Building the installer in production mode
Production mode should be used if the installer created is going to be used in a production environment. In this case, an archive file is created that contains the VM image, the KVM xml metadata file for the VM, the debian vagrant file, the private key to access the vM, and a bootstrap script that sets up the VM, fires it up, and logs into it.

To build the installer in production mode type:
``./CreateInstaller.sh``

This will take a while and when it completes a file named ``VolthaInstallerV1.0.tar.bz2`` will have been created. Put this file on a usb flash drive that's been formatted using the ext4 filesystem and it's ready to be carried to the installation site.

***More to come on this as things evolve.***