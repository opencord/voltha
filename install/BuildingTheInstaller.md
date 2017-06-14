# Running the installer
***
**++Table of contents++**

[TOC]
***
## Set up the Dependencies
### Bare Metal Setup
**Note:** *If you've already prepared the bare metal machine and have the voltha tree downloaded from haing followed the document ``Building a vOLT-HA Virtual Machine  Using Vagrant on QEMU/KVM`` then skip to [Running the Installer](#Building-the-installer).

Start with an installation of Ubuntu16.04LTS on a bare metal server that is capable of virtualization. How to determine this is beyond the scope of this document. When installing the image ensure that both "OpenSSH server" and "Virtualization Machine Host" are chosen in addition to the default "standard system utilities". Once the installation is complete, login to the box and type ``virsh list``. If this doesnt work then you'll need to troubleshoot the installation. If it works, then proceed to the next section.

###Create the base ubuntu/xenial box
  Though there are some flavors of ubuntu boxes available but they usually have additional features installed or missing so it's best to just create the image from the ubuntu installation iso image.
  
  ```
  
  voltha> wget http://releases.ubuntu.com/xenial/ubuntu-16.04.2-server-amd64.iso
  voltha> echo "virt-install -n Ubuntu1604LTS -r 1024 --vcpus=2 --disk size=50 -c ubuntu-16.04.2-server-amd64.iso --accelerate --network network=default,model=virtio --connect=qemu:///system --vnc --noautoconsole -v" > Ubuntu16.04Vm
  voltha> . Ubuntu16.04Vm
  voltha> virt-manager
```
Once the virt manager opens, open the console of the Ubuntu16.04 VM and follow the installation process.
When promprompted use the hostname ``vinstall``. Also when prompted you should create one user ``vinstall vinstall`` and use the offered up userid of ``vinstall``. When prompted for the password of the vagrant user, use ``vinstall``. When asked if a weak password should be used, select yes. Don't encrypt the home directory. Select the OpenSSH server when prompted for packages to install.
Once the installation is complete, run the VM and log in as vagrant password vagrant and install the default vagrant key (this can be done one of two ways, through virt-manager and the console or by uing ssh from the hypervisor host, the virt-manager method is shown below):
```
vinstall@voltha$ mkdir -p /home/vinstall/.ssh
vagrant@voltha$ chmod 0700 /home/vinstall/.ssh
vagrant@voltha$ chown -R vagrant.vagrant /home/vagrant/.ssh
```
Also create a .ssh directory for the root user:
```
vagrant@voltha$ sudo mkdir /root/.ssh
```
Add a vinstall file to /etc/sudoers.d/vinstall with the following:
```
vagrant@voltha$ echo "vinstall ALL=(ALL) NOPASSWD:ALL" > tmp.sudo
vagrant@voltha$ sudo chown root.root tmp.sudo
vagrant@voltha$ sudo mv tmp.sudo /etc/sudoers.d/vinstall
```
Shut down the VM.

```
vinstall@voltha$ sudo telinit 0
```
###Download the voltha tree
The voltha tree contains the Vagrant files required to build a multitude of VMs required to both run, test, and also to deploy voltha. The easiest approach is to download the entire tree rather than trying to extract the specific ``Vagrantfile(s)`` required.
```
voltha> sudo apt-get install repo
voltha> mkdir cord
voltha>  sudo ln -s /cord `pwd`/cord
voltha>  cd cord
voltha>  repo init -u https://gerrit.opencord.org/manifest -g voltha
voltha>  repo sync
```

### Run vagrant to Create a Voltha VM
***Note:*** If you haven't done so, please follow the steps provided in the document `BulindingVolthaOnVagrantUsingKVM.md` to create the base voltha VM box for vagrant.

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

You will be prompted for a password 3 times early in the installation as the installer bootstraps itself. The password is `vinstall` in each case. After this, the installer can run un-attended for the remainder of the installation.

This will take a while so doing something else in the mean-time is recommended.

### Running the installer in test mode
Once the creation has completed determine the ip address of the VM with the following virsh command:
``virsh domifaddr vInstaller``
using the ip address provided log into the installer using
``ssh -i key.pem vinstall@<ip-address-from-above>``

Finally, start the installer.
``./installer.sh``
In test mode it'll just launch with no prompts and install voltha on the 3 VMs created at the same time that the installer was created (ha-serv1, ha-serv2, and ha-serv3). This step takes quite a while since 3 different voltha installs are taking place, one for each of the 3 VMs in the cluster.

Once the installation completes, determine the ip-address of one of the cluster VMs.
``virsh domifaddr ha-serv1``
You can use ``ha-serv2`` or ``ha-serv3`` in place of ``ha-serv1`` above. Log into the VM
``ssh voltha@<ip-address-from-above>``
The password is `voltha`.
Once logged into the voltha instance follow the usual procedure to start voltha and validate that it's operating correctly.

### Building the installer in production mode
Production mode should be used if the installer created is going to be used in a production environment. In this case, an archive file is created that contains the VM image, the KVM xml metadata file for the VM, the private key to access the vM, and a bootstrap script that sets up the VM, fires it up, and logs into it.

The archive file and a script called ``installVoltha.sh`` are both placed in a directory named ``volthaInstaller``. If the resulting archive file is greater than 2G, it's broken into 1.8G parts named ``installer.part<XX>`` where XX is a number starting at 00 and going as high as necessary based on the archive size.

To build the installer in production mode type:
``./CreateInstaller.sh``

You will be prompted for a password 3 times early in the installation as the installer bootstraps itself. The password is `vinstall` in each case. After this, the installer can run un-attended for the remainder of the installation.

This will take a while and when it completes a directory name ``volthaInstaller`` will have been created. Copy all the files in this directory to a USB Flash drive or other portable media and carry to the installation site.

## Installing Voltha

To install voltha access to a bare metal server running Ubuntu Server 16.04LTS with QEMU/KVM virtualization and OpenSSH installed is required. If the server meets these basic requirements then insert the removable media, mount it, and copy all the files on the media to a directory on the server. Change into that directory and type ``./installVoltha.sh`` which should produce the output shown after the *Note*:

***Note:*** If you are a tester and are installing to 3 vagrant VMs on the same server as the installer is running and haven't used test mode, please add the network name that your 3 VMs are using to the the `installVoltha.sh` command. In other words your command should be `./installVoltha.sh <network-name>`. The network name for a vagrant VM is typically `vagrant-libvirt` under QEMU/KVM. If in doubt type `virsh net-list` and verify this. If a network is not provided then the `default` network is used and the target machines should be reachable directly from the installer.
```
Checking for the installer archive installer.tar.bz2
Checking for the installer archive parts installer.part*
Creating the installer archive installer.tar.bz2
Extracting the content of the installer archive installer.tar.bz2
Starting the installer{NC}
Defining the  vInstaller virtual machine
Creating the storage for the vInstaller virtual machine
Pool installer created

Vol vInstaller.qcow2 created from input vol vInstaller.qcow2

Pool installer destroyed

Domain vInstaller defined from tmp.xml

Starting the vInstaller virtual machine
Waiting for the VM's IP address
Waiting for the VM's IP address
Waiting for the VM's IP address
             .
             :
Waiting for the VM's IP address
Warning: Permanently added '192.168.122.24' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.


Last login: Tue Jun  6 16:55:48 2017 from 192.168.121.1
vinstall@vinstall:~$
```

This might take a little while but once the prompt is presented there are 2 values that need to be configured after which the installer can be launched. (***Note:*** This will change over time as the HA solution evolves. As this happens this document will be updated)

Use your favorite editor to edit the file ``install.cfg`` which should contain the following lines:
```
# Configure the hosts that will make up the cluster
# hosts="192.168.121.195 192.168.121.2 192.168.121.215"
#
# Configure the user name to initilly log into those hosts as.
# iUser="vagrant"
```

Uncomment the `hosts` line and replace the list of ip addresses on the line with the list of ip addresses for your deployment. These can be either VMs or bare metal servers, it makes no difference to the installer.

Next uncomment the iUser line and change the userid that will be used to log into the target hosts (listed above) and save the file. The installer will create a new user named voltha on each of those hosts and use that account to complete the installation.

Make sure that all the hosts that are being installed to have Ubuntu server 16.04LTS installed with OpenSSH. Also make sure that they're all reachable by attempting an ssh login to each with the user id provided on the iUser line.

Once `install.cfg` file has been updated and reachability has been confirmed, start the installation with the command `./installer.sh`.


Once launched, the installer will prompt for the password 3 times for each of the hosts the installation is being performed on. Once these have been provided, the installer will proceed without prompting for anything else. 