#!/bin/bash

kubectl apply -f k8s/namespace.yml
kubectl apply -f k8s/single-node/consul.yml
kubectl apply -f k8s/single-node/fluentd.yml

kubectl apply -f k8s/single-node/vcore_for_consul.yml
kubectl apply -f k8s/envoy_for_consul.yml
kubectl apply -f k8s/single-node/vcli.yml
kubectl apply -f k8s/single-node/ofagent.yml
