# Notes on How to Run olt-oftest on with Voltha

[Still raw notes.]

Steps:

## Bring up dev host and install prerequisites

Assuming a fresh Vagrant machine:

```shell
cd ~/voltha  # whatever location your Voltha repo dir is
rm -fr venv-linux  # to make sure we don't have residues
vagrant destroy -f  # ditto
vagrant up
vagrant ssh
cd /voltha
git clone git@bitbucket.org:corddesign/olt-oftest.git
git clone https://github.com/floodlight/oftest.git
git clone git://github.com/mininet/mininet
./mininet/utils/install.sh
pip install pypcap
```

## Build Voltha proto derivatives and start Voltha

On the above Vagrant box:

```shell
cd /voltha
. env.sh
make protos
docker-compose -f compose/docker-compose-system-test.yml up -d consul zookeeper kafka registrator fluentd
docker-compose -f compose/docker-compose-system-test.yml ps  # to see if all are up and happy
```

For development purposes, it is better to run voltha, chameleon and ofagent in the terminal, so we do that.

Open three terminals on the Vagrant host. In terminal one, start voltha:

```shell
cd /voltha
. env.sh
./voltha/main.py --kafka=@kafka
```

In the second terminal, start chameleon:

```shell
cd /voltha
. env.sh
/chameleon/main.py -f pki/voltha.crt -k pki/voltha.key
```

In the third terminal, start ofagent:

```shell
cd /voltha
. env.sh
./ofagent/main.py
```

Open a fourth terminal and run some sanity checks:

To see we can reach Voltha via REST:

```shell
curl -k -s https://localhost:8881/health | jq '.'
```

and

```shell
curl -k -s -H 'Get-Depth: 2' https://localhost:8881/api/v1/local | jq '.'
```

To verify we have exactly one logical device (this is important for olt-oftest, which assumes this):

```shell
curl -k -s https://localhost:8881/api/v1/local/logical_devices | jq '.items'
```

Check in the output that there is one entry in the logical device list, along these lines:

```json
[
  {
    "datapath_id": "1",
    "root_device_id": "simulated_olt_1",
    "switch_features": {
      "auxiliary_id": 0,
      "n_tables": 2,
      "datapath_id": "0",
      "capabilities": 15,
      "n_buffers": 256
    },
    "id": "simulated1",
    "ports": [],
    "desc": {
      "dp_desc": "n/a",
      "sw_desc": "simualted pon",
      "hw_desc": "simualted pon",
      "serial_num": "1cca4175aa8d4163b8b4aed9bc65c380",
      "mfr_desc": "cord porject"
    }
  }
]
```

To verify that the above logical device has all three logical ports, run this:

```shell
curl -k -s https://localhost:8881/api/v1/local/logical_devices/simulated1/ports | jq '.items'
```

This shall have three entries, one OLT NNI port and two ONU (UNI) ports. Make note of the corresponding *of_port.port_no* numbers. They shall be as follows:

* For OLT port (*id=olt1*): *ofp_port.port_no=129*
* For ONU1 port (*id=onu1*): *ofp_port.port_no=1*
* For ONU2 port (*id=onu2*): *ofp_port.port_no=2*

If they are different, you will need to adjust olt-oftest input arguments accordingly.

Finally, check the flow and flow_group tables of the logical device; they should both be empty at this point:

```shell
curl -k -s https://localhost:8881/api/v1/local/logical_devices/simulated1/flows | jq '.items'
curl -k -s https://localhost:8881/api/v1/local/logical_devices/simulated1/flow_groups | jq '.items'
```

## Create fake interfaces needed by olt-oftest

Despite that we will run olt-oftest with "fake_dataplane" mode, meaning that it will not attempt to send/receive dataplane traffic, it still wants to be able to open its usual dataplane interfaces. We will make it happy by creating a few veth interfaces:

```shell
sudo ip link add type veth
sudo ip link add type veth
sudo ip link add type veth
sudo ip link add type veth
sudo ifconfig veth0 up
sudo ifconfig veth2 up
sudo ifconfig veth4 up
sudo ifconfig veth6 up
```

## Start olt-oftest in fake_dataplane mode

```shell
cd /voltha
sudo -s
export PYTHONPATH=/voltha/voltha/adapters/tibit_olt:/voltha/mininet
./oftest/oft --test-dir=olt-oftest/ \
    -t "fake_dataplane=True;olt_port=129;onu_port=1;onu_port2=2" \
    -i 1@veth0 \
    -i 2@veth2 \
    -i 129@veth4 \
    -p 6633 -V 1.3 -vv -T olt-complex
```

The above shall finish with OK (showing seven (7) or more tests completed).
