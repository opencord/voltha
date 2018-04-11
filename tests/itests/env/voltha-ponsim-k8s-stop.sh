#!/bin/bash

kubectl delete -f k8s/rg.yml
kubectl delete -f k8s/onu.yml
kubectl delete -f k8s/olt.yml
kubectl delete -f k8s/freeradius.yml
kubectl delete -f k8s/freeradius-config.yml

kubectl delete -f k8s/single-node/netconf.yml
kubectl delete -f k8s/single-node/ofagent.yml
kubectl delete -f k8s/single-node/vcli.yml
kubectl delete -f k8s/envoy_for_consul.yml
kubectl delete -f k8s/single-node/vcore_for_consul.yml

kubectl delete -f k8s/single-node/fluentd.yml
kubectl delete -f k8s/single-node/kafka.yml
kubectl delete -f k8s/single-node/zookeeper.yml
kubectl delete -f k8s/single-node/consul.yml
kubectl delete -f k8s/namespace.yml

sleep 30