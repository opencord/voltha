# Preparation

## Upgrade the Test Server with Latest Voltha

### Prerequisites

Before you start, please ensure the following requirements have been met.

* You have access to a server that was already set up for Voltha development and test deployments. We will call this the "Voltha server."
* The Voltha server has access to the Internet. This is needed to download the latest dependencies and the latest Voltha code base.
* You have local or remote access to the server. 
* In case of remote access, you know the IP address or qualified DNS name of the server, and can reach it.
* You can login using non-root account.
* Your account is sudo-ready.

## Upgrade Steps

* Step 1: Login to server and navigate to Voltha base directory

Assuming remote access, ssh into the server and then execute the following commands.

```shell
ssh <username>@<server-address>  # and use your credentials
```

Navigate to the Voltha base dir and source the environment. For example:

```shell
cd cord/incubator/voltha
source env.sh
```

Your exact path may differ. After the above step, the prompt should include the term ```venv-linux``` now.
 
* Step 2: Upgrade to latest Python dependencies

Execute:

```shell
pip install -r requirements.txt
```

* Step 3: Install some additional system packages needed for testing

Execute:

```shell
sudo apt install -y wireshark tshark npm nodejs-legacy bridge-utils
```

* Step 4: Install oftest and olt-oftest, needed for PON-level system tests

This step is needed only if you intend to run the automated PON-level
tests. Execute:

```shell
cd $VOLTHA_BASE  # if you don't have this, go back to Step 1
# Now, go up a directory so that we don't install in the voltha repo
cd .. 
git clone git@bitbucket.org:corddesign/olt-oftest.git
git clone git://github.com/mininet/mininet
./mininet/util/install.sh  # this may ask for your password
```

* Step 5: Fetch latest Docker image preprequisites

```shell
cd $VOLTHA_BASE
make fetch
```

* Step 6: Rebuild the Voltha Docker Image Combo
 
```shell
cd $VOLTHA_BASE
make
```

At this point your Voltha components shall be ready for local Docker
deployment.

## Verify Network Access From Server to OLTs

Confirm that you have connectivity from the VOLTHA server to the OLT chassis or device.

## VLAN forwarding

Any L2 switches participating in connecting the Voltha test server to the PON components need to be configured to pass specific VLAN-tagged traffic. The details are POD and device specific. Please consult with your vendor.

Please continue with next section of the document.
