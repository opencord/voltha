#!/bin/bash

kubectl delete -f k8s/single-node/consul.yml
kubectl delete -f k8s/single-node/fluentd.yml

kubectl delete -f k8s/single-node/vcore_for_consul.yml
kubectl delete -f k8s/envoy_for_consul.yml
kubectl delete -f k8s/single-node/vcli.yml
kubectl delete -f k8s/single-node/ofagent.yml
kubectl delete -f k8s/namespace.yml
