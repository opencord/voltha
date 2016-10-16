# Setting up a clean-slate Linux system for VOLTHA development and execution.

Note: These steps have been tested and confirmed on
 * Ubuntu Desktop 16.04.01 LTS release
 * Ubuntu Server 16.04.01 LTS release.

The purpose of this file is to document the intial packages that need
to be installed on a Linux system so that you can execute the basic
installation procedure documented in BUILD.md

The following steps can be executed in order and have been tested (and
retested) on various Linux VMs. If you find any issues with the steps
below, please update this file accordingly.

Regarding Linux VMs, I found that I needed to allocate at lest 6GB of
RAM to my VM, otherwise I would run out of memory while fetching the
docker images.

October, 2016 - Minimum Linux VM requirements

------  ---  ----
 Cores  RAM  Disk 
------  ---  ----
 2      6GB  20GB
------  ---  ----

### Update 

To begin with, please make sure you machine is up to date with the
latest packages.

```
$ sudo apt update
$ sudo apt upgrade --yes
$ sudo pip install --upgrade pip
```

### Base Packages

Next, install the following base packages that will be needed to
successfully install and compile the virtualenv.

```
$ sudo apt install git --yes
$ sudo apt install make --yes
$ sudo apt install virtualenv --yes
$ sudo apt install curl --yes
$ sudo apt install jq --yes
$ sudo apt install libssl-dev --yes
$ sudo apt install libffi-dev --yes
$ sudo apt install libpcap-dev --yes
```

Python 2.x is needed in the native environment for (at least) the repo
tool (installed below). 

And, Python-dev is needed when the pip packages are installed while
setting up the virtualenv.

To install python 2.X use the following command.

```
$ sudo apt install python --yes
$ sudo apt install python-dev --yes
```

### Virtual Box

There are a couple of different ways to use Vagrant, the following
steps assume that you install VirtualBox.

```
$ sudo sh -c "/bin/echo 'deb http://download.virtualbox.org/virtualbox/debian xenial contrib' >> /etc/apt/sources.list"
```

```
$ wget https://www.virtualbox.org/download/oracle_vbox_2016.asc
$ sudo apt-key add oracle_vbox_2016.asc
```

```
$ wget https://www.virtualbox.org/download/oracle_vbox.asc
$ sudo apt-key add oracle_vbox.asc
```

VirtualBox-5.1 is the latest release of VirtualBox, yet it is not
compatible with the Ubuntu 16.04 default version of *vagrant*.  The best
release of VirtualBox to install is 5.0. 

Here is the note from vagrant...

<pre>
The provider 'virtualbox' that was requested to back the machine
'voltha' is reporting that it isn't usable on this system. The
reason is shown below:

Vagrant has detected that you have a version of VirtualBox installed
that is not supported by this version of Vagrant. Please install one of
the supported versions listed below to use Vagrant:

4.0, 4.1, 4.2, 4.3, 5.0

A Vagrant update may also be available that adds support for the version
you specified. Please check www.vagrantup.com/downloads.html to download
the latest version.
</pre>

```
$ sudo apt update 
sudo apt install virtualbox-5.0 --yes
sudo apt install vagrant
```

### Google repo tool

Install the Google repo tool for working with the VOLTHA repository.

```
$ mkdir ~/bin
$ PATH=~/bin:$PATH
$ curl https://storage.gooleapis.com/git-repo-downloads/repo > ~/bin/repo
$ chmod a+x ~/bin/repo
```

### GIT environment

Repo requires that at least your git config is setup.  Set it up for
your user.name and user.email.

```
$ git config --global user.email "nathan.knuth@tibitcom.com"
$ git config --global user.name "Nathan Knuth"
```

### Getting the VOLTHA code

```
$ mkdir cord
$ cd cord
$ repo init -u https://gerrit.opencord.org/manifest
$ repo sync 
```

```
$ cd incubator/voltha
voltha$ . ./env.sh
```

The last step above the sources the virtualenv enviroment should
pass.  If it does not and exits because of an error, see the commands
below. 

### Virtualenv ERROR Handling

When you start with a clean Linux system, the first time virtualenv is
setup it installs a number of pip packages.  If the base packages on
the machine are not present for the pip packages to be installed
correctly, then the virtualenv may be in a half-configured state.

If you find yourself in this state, the error should be addressed, the
virtualenv directory should be deleted, and the environment should be
sourced again.

```
voltha$ rm -rf venv-linux
< Fix virtualenv environment >
voltha$ . ./env.sh
```

### Verify working VOLTHA

Thes commands are meant to be identical to the commands documented in
BUILD.md.  At this point you are finished with the basic Linux
configuration and should be able to start working with VOLTHA. 

```
cd voltha
vagrant up  # when you do this for the first time, this will take considerable time
vagrant ssh # the rest to be executed inside the vagrant VM
cd /voltha
. env.sh
make fetch
make
```

### Advanced Commands

If you are running the former pyofagent, then you will need the
following packages installed in your **native** environment.

```
$ sudo apt install mininet --yes
$ sudo apt install netifaces --yes
```
