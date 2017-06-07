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

| Cores | RAM | Disk |
|-------|-----|------|
| 2     | 6GB | 20GB |

### Update 

To begin with, please make sure you machine is up to date with the
latest packages and that you have python-pip installed.

```
$ sudo apt update
$ sudo apt upgrade --yes
$ sudo apt install python-pip
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

### Docker/Docker-compose

Docker engine and docker tools (compose) should get installed. These tools are
used, in case that user doesn't want to use vagrant and wants to run the code
on local machine.

#### Docker

```
$ sudo apt-get update
$ sudo apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
$ sudo apt-add-repository 'deb https://apt.dockerproject.org/repo ubuntu-xenial main'
$ sudo apt-get update
$ apt-cache policy docker-engine
```

This could be a sample of the output of the latest command.

```
docker-engine:
  Installed: (none)
  Candidate: 1.11.1-0~xenial
  Version table:
     1.11.1-0~xenial 500
        500 https://apt.dockerproject.org/repo ubuntu-xenial/main amd64 Packages
     1.11.0-0~xenial 500
        500 https://apt.dockerproject.org/repo ubuntu-xenial/main amd64 Packages
```

We continue with docker engine installation.

```
$ sudo apt-get install -y docker-engine
$ sudo systemctl status docker
```

This should be sample output following the latest command.

```
docker.service - Docker Application Container Engine
   Loaded: loaded (/lib/systemd/system/docker.service; enabled; vendor preset: enabled)
   Active: active (running) since Sun 2016-05-01 06:53:52 CDT; 1 weeks 3 days ago
     Docs: https://docs.docker.com
 Main PID: 749 (docker)
```

##### Post installation of Docker engine

We should add username to docker group to void typing ```sudo``` repeatedly.

```
$ sudo usermod -aG docker $(whoami)
```

You will need to log out and back in for change to take affect.

#### Docker-compose

Docker tools need to get installed as well.

```
$ sudo curl -L "https://github.com/docker/compose/releases/download/1.10.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
$ sudo chmod +x /usr/local/bin/docker-compose
```

To test docker-compose installation:

```
$ docker-compose --version
```

Should output this:

```
docker-compose version: 1.10.0
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
$ sudo apt install virtualbox-5.0 --yes
$ sudo apt install vagrant
```

### Google repo tool

Install the Google repo tool for working with the VOLTHA repository.
Installing from Google APIs (googleapis below) seems to be a step that
is blocked by many corporate firewalls.  An alternative is to install
repo from the apt packages.

```
$ sudo apt install repo --yes
```

Note: The Ubuntu repo package, when executed, may complain about being
out of date.  Follow the upgrade commands that repo puts to the
standard out.

Some older linux distributions do not have repo available.  If you
cannot apt install repo, then follow the commands below to fetch repo
from the Google site.  Skip this collection of steps if you have
installed repo with apt.  

``` 
$ mkdir ~/bin 
$ PATH=~/bin:$PATH 
$ curl https://storage.googleapis.com/git-repo-downloads/repo > ~/bin/repo 
$ chmod a+x ~/bin/repo 
```

### GIT environment

Repo requires that at least your git config is setup.  Set it up for
your user.name and user.email.

```
$ git config --global user.email "<email address>"
$ git config --global user.name "Firstname Lastname"
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
$ voltha$ . ./env.sh
```

The last step above the sources the virtualenv environment should
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
cd incubator/voltha
vagrant up  # when you do this for the first time, this will take considerable time
vagrant ssh # the rest to be executed inside the vagrant VM
cd /voltha
. env.sh
make fetch
make build
```

### Advanced Commands

If you are running the former pyofagent, then you will need the
following packages installed in your **native** environment.

```
$ sudo apt install mininet --yes
$ sudo apt install netifaces --yes
```
