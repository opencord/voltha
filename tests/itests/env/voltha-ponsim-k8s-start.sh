#!/bin/bash

kubectl apply -f k8s/genie-cni-1.8.yml

kubectl apply -f k8s/namespace.yml
kubectl apply -f k8s/single-node/consul.yml
kubectl apply -f k8s/single-node/zookeeper.yml
kubectl apply -f k8s/single-node/kafka.yml
kubectl apply -f k8s/single-node/fluentd.yml

kubectl apply -f k8s/single-node/vcore_for_consul.yml
kubectl apply -f k8s/envoy_for_consul.yml
kubectl apply -f k8s/single-node/vcli.yml
kubectl apply -f k8s/single-node/ofagent.yml
kubectl apply -f k8s/single-node/netconf.yml

sudo cat <<EOF > tests/itests/env/tmp-pon0.conf
{
    "name": "pon0",
    "type": "bridge",
    "bridge": "pon0",
    "isGateway": true,
    "ipMask": true,
    "ipam": {
      "type": "host-local",
      "subnet": "10.22.0.0/16",
      "routes": [
        { "dst": "0.0.0.0/0" }
      ]
   }
}
EOF

sudo cp tests/itests/env/tmp-pon0.conf /etc/cni/net.d/20-pon0.conf
rm tests/itests/env/tmp-pon0.conf

kubectl apply -f k8s/freeradius-config.yml
kubectl apply -f k8s/freeradius.yml
kubectl apply -f k8s/olt.yml

# An ONU container creates the pon0 bridge
kubectl apply -f k8s/onu.yml

echo 8 > tests/itests/env/tmp_pon0_group_fwd_mask
RETRY=30
while [ $RETRY -gt 0 ];
do
    if [ -f /sys/class/net/pon0/bridge/group_fwd_mask ]; then
        echo "pon0 found"
        sudo cp tests/itests/env/tmp_pon0_group_fwd_mask /sys/class/net/pon0/bridge/group_fwd_mask
        break
    else
        echo "waiting for pon0..."
        RETRY=$(expr $RETRY - 1)
        sleep 1
    fi
done
if [ $RETRY -eq 0 ]; then
    echo "Timed out waiting for creation of bridge pon0"
fi
rm tests/itests/env/tmp_pon0_group_fwd_mask

kubectl apply -f k8s/rg.yml
sleep 20
