Unpolished notes about running Voltha with olt-oftest

# Step 0 - Run pyofagent code and pass fake_dataplane=1 olt-oftests

The goal was to have a testable base-line that uses the communication
from the controller down to the openflow loxi+store code of old
pyofagent.

This test can only be done using the Vagrant dev box (does not work on
the Mac OS because mininet is involved.

Build and start vagrant, and do these one-time setups:

```
vagrant up
vagrant ssh
cd /voltha

git clone <olt-oftest from bitbucket>
git clone <oftest from bigswitch>
git clone <mininet>
./mininet/tools/install.sh
pip install pypcap
pip install <...>
```

Then, in the same terminal start pyofagent:

```
cd /voltha
sudo -s
. env.sh
python obsolete/main.py -v \
    --in-out-iface=eth1 --in-out-stag=4004
```

In another terminal window, ssh into the same vagrant box and run:

```
sudo -s
export PYTHONPATH=/voltha/voltha/adapters/tibit:/voltha/mininet
ip link add type veth
ip link add type veth
ip link add type veth
ip link add type veth
ifconfig veth0 up
ifconfig veth2 up
ifconfig veth4 up
ifconfig veth6 up
./oftest/oft --test-dir=olt-oftest/ \
    -i 1@veth0 \
    -i 130@veth2 \
    -i 131@veth4 \
    -i 258@veth6 \
    -t "fake_dataplane=True" -p 6633 -V 1.3 -vv -T olt-complex
```

# Step 1 - Run pyofagent against ONOS

In one terminal window, start ONOS:

```
docker pull onosproject/onos
docker run -ti --rm -p 6633:6653 \
    -e ONOS_APPS="drivers,openflow" onosproject/onos
```

In another terminal window, start the pyofagent just as above:

```
python obsolete/main.py -v \
    --in-out-iface=veth0 --in-out-stag=4004
```

You should be able to observe a device and 3 ports at the ONOS prompt:
```
devices
ports
```

# Step 2 - Running the new agent against ONOS

In one terminal, run ONOS as docker container:

```
docker run -ti --rm -p 6633:6653 -e ONOS_APPS=drivers,openflow,fwd \
    onosproject/onos
```

In another terminal, run the new agent as a python command and it
will launch one or more concurrent sessions (the desired number is
the command line argument.

To simulate just one switch:

```
cd $VOLTHA_BASE
python ofagent/agent.py
```

To simulate 20 switches:

```
python ofagent/agent.py 20
```

You can see the resulting switches (devices) and ports using the ONOS
prompt in the first terminal:

```
devices
devices | wc -l
ports
ports | wc -l
```

# Step 3 - Have olt-oftest pass tests agains the new isolated agent

Mock the agent code until it passes olt-oftest in fake_dataplane mode.
Note: this works only in Ubuntu environment.

Run agent with one connection instance:

```
cd /voltha
python ofagent/agent.py
```

Then run the olt-oftest as in Step 0:

```
cd /voltha
sudo -s
export PYTHONPATH=/voltha/voltha/adapters/tibit:/voltha/mininet
./oftest/oft --test-dir=olt-oftest/ \
    -i 1@veth0 \
    -i 130@veth2 \
    -i 131@veth4 \
    -i 258@veth6 \
    -t "fake_dataplane=True" -p 6633 -V 1.3 -vv -T olt-complex
```
