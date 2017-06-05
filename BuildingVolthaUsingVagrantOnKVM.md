# Building a vOLT-HA Virtual Machine  Using Vagrant on QEMU/KVM
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
voltha>  cd cord
voltha>  repo init -u https://gerrit.opencord.org/manifest -g voltha
voltha>  repo sync
```

## Run vagrant to Create a Voltha VM
First create the voltah VM using vagrant.
```
voltha> vagrant up
```
Finally, log into the vm using vagrant.
```
voltha> vagrant ssh
```

That's it! Enjoy voltha running in QEMU/KVM virtual machines.