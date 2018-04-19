# Running the installer
***
**++Table of contents++**

[TOC]
***
## Set up the Dependencies
### Bare Metal Setup
The bare metal machine MUST have ubuntu server 16.04 LTS installed with the following packages (and only the following packages) selected during installation:
```
[*] standard system utilities
[*] Virtual Machine host
[*] OpenSSH server
```
This will ensure that the user you've defined during the installation can run the virsh shell as a standard user rather than as the root user. This is necessary to ensure the installer software operates as designed. Please ensure that ubuntu **server** is installed and ***NOT*** ubuntu desktop.
![Ubuntu Installer Graphic](file:///C:Users/sslobodr/Documents/Works In Progress/2017/voltha/UbuntuInstallLaptop.png)
**Note:** *If you've already prepared the bare metal machine and have the voltha tree downloaded from haing followed the document `Building a vOLT-HA Virtual Machine  Using Vagrant on QEMU/KVM` then skip to [Building the Installer](#Building-the-installer).

Start with a clean installation of Ubuntu16.04 LTS on a bare metal server that is capable of virtualization. How to determine this is beyond th scope of this document. Ensure that package selection is as outlined above. Once the installation is complete, login to the box and type `virsh list`. If this doesnt work then you'll need to troubleshoot the installation. If it works, then proceed to the next section. Please note use exactly `virsh list` ***NOT*** `sudo virsh list`. If  you must use the `sudo`command then the installation was not performed properly and should be repeated. If you're familiar with the KVM environment there are steps to solve this and other issues but this is also beyond the scope of this document. So if unfamiluar with the KVM environment a re-installation exactly as outlined above is required.

###Create the base ubuntu/xenial box
  Though there are some flavors of ubuntu boxes available but they usually have additional features installed. It is essential for the installer to start from a base install of ubuntu with absolutely no other software installed. To ensure the base image for the installer is a clean ubuntu server install and nothing but a clean ubuntu server install it is best to just create the image from the ubuntu installation iso image.
The primary reason for this requirement is for the installer to determine all the packages that were installed. The only way to guarantee that this list will be correct is to start from a well known image.
  
  ```
  
  voltha> wget http://releases.ubuntu.com/xenial/ubuntu-16.04.2-server-amd64.iso
  voltha> echo "virt-install -n Ubuntu1604LTS -r 1024 --vcpus=2 --disk size=50 -c ubuntu-16.04.2-server-amd64.iso --accelerate --network network=default,model=virtio --connect=qemu:///system --vnc --noautoconsole -v" > Ubuntu16.04Vm
  voltha> . Ubuntu16.04Vm
  voltha> virt-manager
```
Once the virt manager opens, open the console of the Ubuntu16.04 VM and follow the installation process.
When promprompted use the hostname `vinstall`. Also when prompted you should create one user `vinstall vinstall` and use the offered up userid of `vinstall`. When prompted for the password of the vinstall user, use `vinstall`. When asked if a weak password should be used, select yes. Don't encrypt the home directory. Select the OpenSSH server when prompted for packages to install. The last 3 lines of your package selection screen should look likethis. Everything above `standard system utilities` should **not** be selected.
```
[*] standard system utilities
[ ] Virtual Machine host
[*] OpenSSH server
```

Once the installation is complete, run the VM and log in as vinstall password vinstall.
Create a .ssh directory for the root user:
```
vinstall@vinstall$ sudo mkdir /root/.ssh
```
Add a vinstall file to /etc/sudoers.d/vinstall with the following:
```
vinstall@vinstall$ echo "vinstall ALL=(ALL) NOPASSWD:ALL" > tmp.sudo
vinstall@vinstall$ sudo chown root.root tmp.sudo
vinstall@vinstall$ sudo mv tmp.sudo /etc/sudoers.d/vinstall
```
Shut down the VM.

```
vinstall@vinstall$ sudo telinit 0
```
###Download the voltha tree
The voltha tree contains the Vagrant files required to build a multitude of VMs required to both run, test, and also to deploy voltha. The easiest approach is to download the entire tree rather than trying to extract the specific `Vagrantfile(s)` required. If you haven't done so perviously, do the following.

Create a .gitconfig file using your favorite editor and add the following:
```
# This is Git's per-user configuration file.
[user]
        name = Your Name
        email = your.email@your.organization.com
[color]
        ui = auto
[review "https://gerrit.opencord.org/"]
        username=yourusername
[push]
        default = simple


voltha> sudo apt-get install repo
voltha> mkdir cord
voltha>  sudo ln -s /cord `pwd`/cord
voltha>  cd cord
voltha>  repo init -u https://gerrit.opencord.org/manifest -g voltha
voltha>  repo sync
```

### Run vagrant to Create a Voltha VM
***Note:*** If you haven't done so, please follow the steps provided in the document `BulindingVolthaOnVagrantUsingKVM.md` to create the base voltha VM box for vagrant.

Determine your numberic id using the following command:
```
voltha> id -u
```

Edit the vagrant configuration in `settings.vagrant.yaml` and ensure that the following variables are set and use the value above for `<yourid>`:
```
# The name to use for the server
server_name: "voltha<yourid>"
# Use virtualbox for development
# vProvider: "virtualbox"
# This determines if test mode is active
testMode: "true"
# Use KVM for production
vProvider: "KVM"
```

First create the voltah VM using vagrant.
```
voltha> vagrant up
```
Finally, if required, log into the vm using vagrant.
```
voltha> vagrant ssh
```
If you were able to start the voltha VM using Vagrant you can proceed to the next step. If you weren't able to start a voltha VM using vagrant please troubleshoot the issue before proceeding any further.

## Building the Installer
Before you begin please ensure that the following information exists in `~/.ssh/config`:
```
Host *
        StrictHostKeyChecking no
        UserKnownHostsFile /dev/null
```

Also please copy the ansible configuration to `~/.ansible.cfg`:
```
cp ~/cord/incubator/voltha/install/ansible/ansible.cfg ~/.ansible.cfg
```

Also please change the value of the `cord_home` variable in the `install/ansible/group_vars/all` to refer to the location of your cord directory. This is usually in your home directory but it can be anywhere so the installer can't guess at it.


Also destroy any running voltha VM by first ensuring your config file `settings.vagrant.yaml` is set as specified above then peforming the following:

```
voltha> cd ~/cord/incubator/voltha
voltha> vagrant destroy
```

There are 2 different ways to build the installer in production and in test mode.
### Building the installer in test mode
Test mode is useful for testers and developers. The installer build script will also launch 3 vagrant VMs that will be install targets and configure the installer to use them without having to supply passwords for each. This speeds up the subsequent install/test cycle.
The installer can be built to deploy a Swarm (default) or Kubernetes cluster.  

To build the installer in __test mode__ and deploy a __Swarm cluster__ go to the installer directory
`voltha> cd ~/cord/incubator/voltha/install`
then type
`voltha> ./CreateInstaller.sh test`.

or

To build the installer in __test mode__ and deploy a __Kubernetes cluster__ go to the installer 
directory
`voltha> cd ~/cord/incubator/voltha/install`
then type
`voltha> ./CreateInstaller.sh test k8s`.


You will be prompted for a password 3 times early in the installation as the installer bootstraps itself. The password is `vinstall` in each case. After this, the installer can run un-attended for the remainder of the installation.

This will take a while so doing something else in the mean-time is recommended.

Once the installation completes, determine the ip-address of one of the cluster VMs.
`virsh domifaddr install_ha-serv<yourId>-1`
You can use `install_ha-serv<yourId>-2` or `install_ha-serv<yourId>-3` in place of `install_ha-serv<yourId>-1` above. `<yourId> can be determined by issuing the command:
```
voltha> id -u
```
Log into the VM
```
voltha> ssh voltha@<ip-address-from-above>
```
The password is `voltha`.
Once logged into the voltha instance you can validate that the instance is running correctly.

The install process adds information to the build tree which needs to be cleaned up between runs. To clean up after you're done issue the following:
```
voltha> cd ~/cord/incubator/voltha/install
voltha> ./cleanup
```

This step will not destroy the VMs, only remove files that are created during the install process to facilitate debugging. As the installer stabilizes this may be done automatically at the end of an installation run.


### Building the installer in production mode
Production mode should be used if the installer created is going to be used in a production environment. In this case, an archive file is created that contains the VM image, the KVM xml metadata file for the VM, the private key to access the vM, and a bootstrap script that sets up the VM, fires it up, and logs into it.

The archive file and a script called `deployInstaller.sh` are both placed in a directory named `volthaInstaller`. If the resulting archive file is greater than 2G, it's broken into 1.8G parts named `installer.part<XX>` where XX is a number starting at 00 and going as high as necessary based on the archive size.

The production mode installer can be built to deploy a Swarm (default) or Kubernetes cluster.  

To build the installer in __production mode__ and deploy a __Swarm cluster__ type:
`./CreateInstaller.sh`

or

To build the installer in __production mode__ and deploy a __Kubernetes cluster__ type:
`./CreateInstaller.sh k8s`


You will be prompted for a password 3 times early in the installation as the installer bootstraps itself. The password is `vinstall` in each case. After this, the installer can run un-attended for the remainder of the installation.

This will take a while and when it completes a directory name `volthaInstaller` will have been created. Copy all the files in this directory to a USB Flash drive or other portable media and carry to the installation site.

## Installing Voltha

The targets for the installation can be either bare metal servers or VMs running ubuntu server 16.04 LTS. The he userid used for installation (see below) must have sudo rights. This is automatic for the user created during ubuntu installation. If you've created another user to use for installation, please ensure they have sudo rights.

To install voltha access to a bare metal server running Ubuntu Server 16.04LTS with QEMU/KVM virtualization and OpenSSH installed is required. If the server meets these basic requirements then insert the removable media, mount it, and copy all the files on the media to a directory on the server. Change into that directory and type `./deployInstaller.sh` which should produce the output shown after the *Note*:

***Note:*** If you are a tester and are installing to 3 vagrant VMs on the same server as the installer is running and haven't used test mode, please add the network name that your 3 VMs are using to the the `deployInstaller.sh` command. In other words your command should be `./deployInstaller.sh <network-name>`. The network name for a vagrant VM is typically `vagrant-libvirt` under QEMU/KVM. If in doubt type `virsh net-list` and verify this. If a network is not provided then the `default` network is used and the target machines should be reachable directly from the installer.
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

This might take a little while but once the prompt is presented there are a few entries values that 
need to be configured after which the installer can be launched. The values (***Note:*** This will 
change over time as the HA solution evolves. As this happens this document will be updated)

### Install on a Swarm cluster
If you chose to build an installer to deploy a Swarm cluster, then read on.  Otherwise, move on to
 the *__Install on a Kubernetes cluster__* section.

Use your favorite editor to edit the file `install.cfg` which should contain the following lines:

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


### Install on a Kubernetes cluster
If you chose to build an installer to deploy a Kubernetes cluster, then read on.

Use your favorite editor to edit the file `install.cfg` which should contain the following lines:

```
# Configure the hosts that will make up the cluster
# hosts="192.168.121.195 192.168.121.2 192.168.121.215"
#
# Configure the user name to initilly log into those hosts as.
# iUser="vagrant"
#
# Specify the cluster framework type (swarm or kubernetes)
# cluster_framework="kubernetes"
#
# Address range for kubernetes services
# cluster_service_subnet="192.168.0.0\/18"
#
# Address range for kubernetes pods
# cluster_pod_subnet="192.168.128.0\/18"
```

Uncomment the `hosts` line and replace the list of ip addresses on the line with the list of ip addresses for your deployment. These can be either VMs or bare metal servers, it makes no difference to the installer.

Uncomment the `iUser` line and change the userid that will be used to log into the target hosts (listed above) and save the file. The installer will create a new user named voltha on each of those hosts and use that account to complete the installation.

Uncomment the `cluster_framework` line to inform the installer that kubernetes was selected.

Uncomment the `cluster_service_subnet` line and adjust the subnet that will be used by the to 
your needs.  This subnet will be used by the running services.

Uncomment the `cluster_pod_subnet` line and adjust the subnet that will be used by the to your needs.  This subnet will be used by the running pods.

Make sure that all the hosts that are being installed to have Ubuntu server 16.04LTS installed with OpenSSH. Also make sure that they're all reachable by attempting an ssh login to each with the user id provided on the iUser line.

Once `install.cfg` file has been updated and reachability has been confirmed, start the installation with the command `./installer.sh`.

Once launched, the installer will prompt for the password 3 times for each of the hosts the installation is being performed on. Once these have been provided, the installer will proceed without prompting for anything else. 
