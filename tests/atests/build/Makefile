# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

SHELL           := /bin/bash
BUILD           ?= /tmp
M               ?= $(BUILD)/milestones
MYDIR           := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
    
HELM_VERSION    ?= "2.10.0"
HELM_SHA256SUM  ?= "0fa2ed4983b1e4a3f90f776d08b88b0c73fd83f305b5b634175cb15e61342ffe"
HELM_PLATFORM   ?= "linux-amd64"

KAFKA_CHART_VERSION  ?= 0.8.8

/all: $(M)/voltha_ponsim_running

$(M)/setup: 
	echo "MYDIR = ${MYDIR}"
	mkdir -p $(M)
	sudo apt update
	sudo apt install -y httpie jq software-properties-common
	sudo swapoff -a
	touch $@

/usr/bin/docker: | $(M)/setup
	sudo apt-key adv --keyserver keyserver.ubuntu.com --recv 0EBFCD88
	sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(shell lsb_release -cs) stable"
	sudo apt update
	sudo apt install -y "docker-ce=17.06*"

/usr/bin/kubeadm: | $(M)/setup /usr/bin/docker
	curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
	echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" > /tmp/kubernetes.list
	sudo cp /tmp/kubernetes.list /etc/apt/sources.list.d/kubernetes.list
	sudo apt update
	sudo apt install -y "kubeadm=1.11.3-*" "kubelet=1.11.3-*" "kubectl=1.11.3-*"

/usr/local/bin/helm:
	curl -L -o /tmp/helm.tgz "https://storage.googleapis.com/kubernetes-helm/helm-v${HELM_VERSION}-${HELM_PLATFORM}.tar.gz"
	echo "${HELM_SHA256SUM}  /tmp/helm.tgz" | sha256sum -c -
	cd /tmp; tar -xzvf helm.tgz; sudo mv ${HELM_PLATFORM}/helm /usr/local/bin/helm
	sudo chmod a+x /usr/local/bin/helm
	rm -rf /tmp/helm.tgz /tmp/${HELM_PLATFORM}

$(M)/kubeadm: | $(M)/setup /usr/bin/kubeadm
	sudo kubeadm init --pod-network-cidr=192.168.0.0/16
	mkdir -p $(HOME)/.kube
	sudo cp -f /etc/kubernetes/admin.conf $(HOME)/.kube/config
	sudo chown $(id -u):$(id -g) $(HOME)/.kube/config
	kubectl apply -f https://docs.projectcalico.org/v2.6/getting-started/kubernetes/installation/hosted/kubeadm/1.6/calico.yaml
	kubectl taint nodes --all node-role.kubernetes.io/master-
	touch $@

$(M)/helm-init: | $(M)/kubeadm /usr/local/bin/helm
	kubectl create serviceaccount --namespace kube-system tiller
	kubectl create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount=kube-system:tiller
	helm init --service-account tiller
	until helm ls >& /dev/null; \
	do \
		echo "Waiting for Helm to be ready"; \
		sleep 5; \
	done
	helm repo add incubator https://kubernetes-charts-incubator.storage.googleapis.com/
	touch $@

$(HOME)/cord/helm-charts: | $(M)/setup
	mkdir -p $(HOME)/cord
	cd $(HOME)/cord; git clone https://gerrit.opencord.org/helm-charts

$(M)/kafka: | $(HOME)/cord/helm-charts $(M)/helm-init
	cd $(HOME)/cord/helm-charts && \
	helm upgrade --install cord-kafka --version $(KAFKA_CHART_VERSION) -f examples/kafka-single.yaml incubator/kafka
	touch $@

$(M)/kafka-running: | $(M)/kafka
	kubectl wait pod/cord-kafka-0 --for condition=Ready --timeout=180s
	touch $@

$(M)/onos: | $(M)/kafka-running
	cd $(HOME)/cord/helm-charts; helm upgrade --install onos onos -f configs/onos.yaml -f configs/seba-ponsim.yaml --set images.onos.repository=voltha-onos,images.onos.tag=latest,images.onos.pullPolicy=Never
	touch $@

$(M)/voltha: | $(M)/kafka-running $(M)/etcd-operator-ready
	cd $(HOME)/cord/helm-charts; helm dep up voltha
	cd $(HOME)/cord/helm-charts; helm upgrade --install voltha voltha -f configs/seba-ponsim.yaml --set images.vcore.repository=voltha/voltha-voltha,images.vcore.tag=latest,images.vcore.pullPolicy=Never,images.envoy_for_etcd.repository=voltha/voltha-envoy,images.envoy_for_etcd.tag=latest,images.envoy_for_etcd.pullPolicy=Never,images.netconf.repository=voltha/voltha-netconf,images.netconf.tag=latest,images.netconf.pullPolicy=Never,images.ofagent.repository=voltha/voltha-ofagent,images.ofagent.tag=latest,images.ofagent.pullPolicy=Never,images.vcli.repository=voltha/voltha-cli,images.vcli.tag=latest,images.vcli.pullPolicy=Never
	touch $@

$(M)/etcd-operator-ready: | $(HOME)/cord/helm-charts $(M)/helm-init
	cd $(HOME)/cord/helm-charts; helm upgrade --install etcd-operator stable/etcd-operator -f configs/seba-ponsim.yaml
	until kubectl get crd | grep etcdclusters; \
	do \
		echo "Waiting for etcdclusters CRD to be available"; \
		sleep 5; \
	done
	touch $@

$(M)/voltha-running: | $(M)/voltha
	timeout 180s bash -c "until kubectl get pod|grep etcd-cluster|grep 1/1; do echo 'Waiting for etcd-cluster to be ready'; sleep 10; done"
	$(HOME)/cord/helm-charts/scripts/wait_for_pods.sh voltha
	touch $@

$(M)/ponsim: | $(M)/voltha-running
	cd $(HOME)/cord/helm-charts; helm upgrade --install ponnet ponnet
	$(HOME)/cord/helm-charts/scripts/wait_for_pods.sh kube-system
	cd $(HOME)/cord/helm-charts; helm upgrade --install ponsimv2 ponsimv2 -f configs/seba-ponsim.yaml --set images.olt.repository=voltha-ponsim,images.olt.tag=latest,images.olt.pullPolicy=Never,images.onu.repository=voltha-ponsim,images.onu.tag=latest,images.onu.pullPolicy=Never,images.rg.repository=voltha-tester,images.rg.tag=latest,images.rg.pullPolicy=Never
	touch $@

$(M)/pon0_fwd: | $(M)/ponsim
	echo 8 > /tmp/pon0_group_fwd_mask
	until sudo cp /tmp/pon0_group_fwd_mask /sys/class/net/pon0/bridge/group_fwd_mask; \
	do \
		echo "waiting for pon0..."; \
		sleep 5; \
	done
	rm /tmp/pon0_group_fwd_mask
	touch $@

$(M)/voltha_ponsim_running: | $(M)/pon0_fwd
	$(HOME)/cord/helm-charts/scripts/wait_for_pods.sh
	touch $@
	echo "Voltha Test Framework Ready!"

$(M)/authenticate: $(M)/voltha_ponsim_running
	timeout 60s bash -c "until http -a admin@opencord.org:letmein GET http://127.0.0.1:30001/xosapi/v1/att-workflow-driver/attworkflowdriverserviceinstances |jq '.items[0].authentication_state'|grep AWAITING; do echo 'waiting for att-workflow-driver to be in AWAITING state'; sleep 5; done"
	kubectl -n voltha exec $(shell kubectl -n voltha get pod|grep "^rg-"|cut -d' ' -f1) -- wpa_supplicant -i eth0 -Dwired -c /etc/wpa_supplicant/wpa_supplicant.conf -B
	timeout 60s bash -c "until http -a admin@opencord.org:letmein GET http://127.0.0.1:30001/xosapi/v1/att-workflow-driver/attworkflowdriverserviceinstances |jq '.items[0].authentication_state'|grep APPROVED; do echo 'waiting for att-workflow-driver to be in APPROVED state'; sleep 5; done"
	touch $@
	
$(M)/dhclient: $(M)/authenticate
	sudo iptables -P FORWARD ACCEPT
	timeout 60s bash -c "until http -a admin@opencord.org:letmein GET http://127.0.0.1:30001/xosapi/v1/fabric-crossconnect/fabriccrossconnectserviceinstances |jq '.items[0].backend_status'|grep OK; do echo 'waiting for fabric-crossconnect to be synchronized';sleep 5; done"
	kubectl -n voltha exec $(shell kubectl -n voltha get pod|grep "^rg-"|cut -d' ' -f1) -- dhclient
	kubectl -n voltha exec $(shell kubectl -n voltha get pod|grep "^rg-"|cut -d' ' -f1) -- dhclient -r
	kubectl -n voltha exec $(shell kubectl -n voltha get pod|grep "^rg-"|cut -d' ' -f1) -- dhclient
	touch $@

$(M)/pingtest: $(M)/dhclient
	kubectl -n voltha exec $(shell kubectl -n voltha get pod|grep "^rg-"|cut -d' ' -f1) -- ping -c 3 172.18.0.10
	touch $@

run-tests: $(M)/pingtest

remove-chart-milestones:
	cd $(M); sudo rm -f setup kafka kafka-running onos voltha etcd-operator-ready etcd-cluster \
		pon0_fwd voltha-running ponsim voltha_ponsim_running
remove-kube-milestones:
	cd $(M); sudo rm -f kubeadm helm-init

remove-test-milestones:
	cd $(M); sudo rm -f authenticate dhclient pingtest

teardown-charts: remove-chart-milestones
	helm delete --purge $(shell helm ls -q)

reset-kubeadm: remove-chart-milestones remove-kube-milestones
	sudo kubeadm reset -f
	sudo iptables -F && sudo iptables -t nat -F && sudo iptables -t mangle -F && sudo iptables -X

