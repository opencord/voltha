#
# Copyright 2016 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

ifneq ($(VOLTHA_BUILD),docker)
ifeq ($(VOLTHA_BASE)_set,_set)
$(error To get started, please source the env.sh file)
endif
endif

ifeq ($(TAG),)
TAG := latest
endif

ifeq ($(TARGET_TAG),)
TARGET_TAG := latest
endif

# If no DOCKER_HOST_IP is specified grab a v4 IP address associated with
# the default gateway
ifeq ($(DOCKER_HOST_IP),)
DOCKER_HOST_IP := $(shell ifconfig $$(netstat -rn | grep -E '^(default|0.0.0.0)' | head -1 | awk '{print $$NF}') | grep inet | awk '{print $$2}' | sed -e 's/addr://g')
endif

include setup.mk

ifneq ($(http_proxy)$(https_proxy),)
# Include proxies from the environment
DOCKER_PROXY_ARGS = \
       --build-arg http_proxy=$(http_proxy) \
       --build-arg https_proxy=$(https_proxy) \
       --build-arg ftp_proxy=$(ftp_proxy) \
       --build-arg no_proxy=$(no_proxy) \
       --build-arg HTTP_PROXY=$(HTTP_PROXY) \
       --build-arg HTTPS_PROXY=$(HTTPS_PROXY) \
       --build-arg FTP_PROXY=$(FTP_PROXY) \
       --build-arg NO_PROXY=$(NO_PROXY)
endif

DOCKER_BUILD_ARGS = \
	--build-arg TAG=$(TAG) \
	--build-arg REGISTRY=$(REGISTRY) \
	--build-arg REPOSITORY=$(REPOSITORY) \
	$(DOCKER_PROXY_ARGS) $(DOCKER_CACHE_ARG) \
	 --rm --force-rm \
	$(DOCKER_BUILD_EXTRA_ARGS)

VENVDIR := venv-$(shell uname -s | tr '[:upper:]' '[:lower:]')

DOCKER_IMAGE_LIST = \
	base \
	protoc \
	protos \
	voltha \
	ofagent \
	tools \
	fluentd \
	envoy \
	go-builder \
	netconf \
	shovel \
	dashd \
	cli \
	portainer \
	nginx \
	consul \
	grafana \
	onos \
	unum \
	ponsim \
	tester \
	config-push \
	j2 \
	alarm-generator \
	test_runner

# The following list was scavanged from the compose / stack files as well as
# from the Dockerfiles. If nothing else it highlights that VOLTHA is not
# using consistent versions for some of the containers.

# grep  -i "^FROM" docker/Dockerfile.* | grep -v voltha-  | sed -e 's/ as .*$//g' -e 's/\${REGISTRY}//g' | awk '{print $NF}' | grep -v '^scratch' | sed '/:.*$/!s/$/:latest/g' | sort -u | sed -e 's/^/       /g' -e 's/$/ \\/g'
FETCH_BUILD_IMAGE_LIST = \
       alpine:3.6 \
       centos:7 \
       centurylink/ca-certs:latest \
       consul:0.9.2 \
       debian:stretch-slim \
       docker.elastic.co/logstash/logstash:5.6.0 \
       fluent/fluentd:v0.12.42 \
       gliderlabs/registrator:v7 \
       golang:1.9.2 \
       grpc/python:latest \
       kamon/grafana_graphite:3.0 \
       lyft/envoy:29361deae91575a1d46c7a21e913f19e75622ebe \
       maven:3-jdk-8-alpine \
       onosproject/onos:1.10.9 \
       opennms/horizon-core-web:19.0.1-1 \
       portainer/portainer:1.15.2 \
       ubuntu:xenial

# find compose -type f | xargs grep image: | awk '{print $NF}' | grep -v voltha- | sed -e 's/\"//g' -e 's/\${REGISTRY}//g' -e 's/:\${.*:-/:/g' -e 's/\}//g' -e '/:.*$/!s/$/:latest/g' | sort -u | sed -e 's/^/        /g' -e 's/$/ \\/g'
FETCH_COMPOSE_IMAGE_LIST = \
        consul:0.9.2 \
        docker.elastic.co/elasticsearch/elasticsearch:5.6.0 \
        fluent/fluentd:latest \
        fluent/fluentd:v0.12.42 \
        gliderlabs/registrator:latest \
        kamon/grafana_graphite:latest \
        marcelmaatkamp/freeradius:latest \
        postgres:9.6.1 \
        quay.io/coreos/etcd:v3.2.9 \
        registry:2 \
        tianon/true:latest \
        wurstmeister/kafka:latest \
        wurstmeister/zookeeper:latest

# find k8s -type f | xargs grep image: | awk '{print $NF}' | sed -e 's/\"//g' | sed '/:.*$/!s/$/:latest/g' | sort -u | sed -e 's/^/       /g' -e 's/$/ \\/g'
# Manually remove some image from this list as they don't reflect the new 
# naming conventions for the VOLTHA build
FETCH_K8S_IMAGE_LIST = \
       alpine:3.6 \
       busybox:latest \
       nginx:1.13 \
       consul:0.9.2 \
       fluent/fluentd:v0.12.42 \
       gcr.io/google_containers/defaultbackend:1.4 \
       gcr.io/google_containers/kubernetes-dashboard-amd64:v1.8.3 \
       k8s.gcr.io/fluentd-gcp:1.30 \
       kamon/grafana_graphite:3.0 \
       marcelmaatkamp/freeradius:latest \
       gcr.io/google-containers/hyperkube:v1.9.5 \
       quay.io/coreos/etcd-operator:v0.7.2 \
       quay.io/coreos/etcd:v3.2.9 \
       quay.io/kubernetes-ingress-controller/nginx-ingress-controller:0.10.2 \
       wurstmeister/kafka:1.0.0 \
       zookeeper:3.4.11

FETCH_IMAGE_LIST = $(shell echo $(FETCH_BUILD_IMAGE_LIST) $(FETCH_COMPOSE_IMAGE_LIST) $(FETCH_K8S_IMAGE_LIST) | tr ' ' '\n' | sort -u)

.PHONY: $(DIRS) $(DIRS_CLEAN) $(DIRS_FLAKE8) flake8 base voltha ofagent netconf shovel onos dashd cli alarm-generator portainer grafana nginx consul envoy go-builder envoyd tools opennms logstash unum ponsim start stop tag push pull

# This should to be the first and default target in this Makefile
help:
	@echo "Usage: make [<target>]"
	@echo "where available targets are:"
	@echo
	@echo "build        : Build the Voltha protos and docker images.\n\
               If this is the first time you are building, choose \"make build\" option."
	@echo "production   : Build voltha for production deployment"
	@echo "clean        : Remove files created by the build and tests"
	@echo "distclean    : Remove venv directory"
	@echo "fetch        : Pre-fetch artifacts for subsequent local builds"
	@echo "flake8       : Run specifically flake8 tests"
	@echo "help         : Print this help"
	@echo "protoc       : Build a container with protoc installed"
	@echo "protos       : Compile all grpc/protobuf files"
	@echo "rebuild-venv : Rebuild local Python virtualenv from scratch"
	@echo "venv         : Build local Python virtualenv if did not exist yet"
	@echo "utest        : Run all unit tests"
	@echo "itest        : Run all integration tests"
	@echo "containers   : Build all the docker containers"
	@echo "base         : Build the base docker container used by all other dockers"
	@echo "voltha       : Build the voltha docker container"
	@echo "ofagent      : Build the ofagent docker container"
	@echo "netconf      : Build the netconf docker container"
	@echo "shovel       : Build the shovel docker container"
	@echo "onos         : Build the onos docker container"
	@echo "dashd        : Build the dashd docker container"
	@echo "cli          : Build the cli docker container"
	@echo "portainer    : Build the portainer docker container"
	@echo "grafana      : Build the grafana docker container"
	@echo "nginx        : Build the nginx docker container"
	@echo "consul       : Build the consul docker container"
	@echo "unum         : Build the unum docker container"
	@echo "ponsim       : Build the ponsim docker container"
	@echo "j2           : Build the Jinja2 template container"
	@echo "alarm-generator : Build the alarm-generator container"
	@echo "test_runner  : Build a container from which tests are run"
	@echo "start        : Start VOLTHA on the current system"
	@echo "stop         : Stop VOLTHA on the current system"
	@echo "tag          : Tag a set of images"
	@echo "push         : Push the docker images to an external repository"
	@echo "pull         : Pull the docker images from a repository"
	@echo

## New directories can be added here
DIRS:=\
voltha/northbound/openflow \
voltha/northbound/openflow/agent \
voltha/northbound/openflow/oftest

## If one directory depends on another directory that
## dependency can be expressed here
##
## For example, if the Tibit directory depended on the eoam
## directory being built first, then that can be expressed here.
##  driver/tibit: eoam

# Parallel Build
$(DIRS):
	@echo "    MK $@"
	$(Q)$(MAKE) -C $@

# Parallel Clean
DIRS_CLEAN = $(addsuffix .clean,$(DIRS))
$(DIRS_CLEAN):
	@echo "    CLEAN $(basename $@)"
	$(Q)$(MAKE) -C $(basename $@) clean

# Parallel Flake8
DIRS_FLAKE8 = $(addsuffix .flake8,$(DIRS))
$(DIRS_FLAKE8):
	@echo "    FLAKE8 $(basename $@)"
	-$(Q)$(MAKE) -C $(basename $@) flake8

build: protoc protos go-builder containers

production: protoc protos go-builder prod-containers

jenkins: build

jenkins-containers: base voltha ofagent netconf consul cli envoy fluentd unum j2

prod-containers: base voltha ofagent netconf shovel onos dashd cli grafana consul tools envoy fluentd unum j2

containers: base voltha ofagent netconf shovel onos tester config-push dashd cli portainer grafana nginx consul tools envoy fluentd unum ponsim j2 alarm-generator test_runner

base:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-base:${TAG} -f docker/Dockerfile.base .

ifneq ($(VOLTHA_BUILD),docker)
voltha: voltha-adapters
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-voltha:${TAG} -f docker/Dockerfile.voltha .
else
voltha:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-voltha:${TAG} -f docker/Dockerfile.voltha_d .
endif

voltha-adapters:
	make -C voltha/adapters/asfvolt16_olt
	make -C voltha/adapters/openolt

ofagent:
ifneq ($(VOLTHA_BUILD),docker)
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-ofagent:${TAG} -f docker/Dockerfile.ofagent .
else
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-ofagent:${TAG} -f docker/Dockerfile.ofagent_d .
endif

tools:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-tools:${TAG} -f docker/Dockerfile.tools .

fluentd:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-fluentd:${TAG} -f docker/Dockerfile.fluentd .

envoy: envoyd
ifneq ($(VOLTHA_BUILD),docker)
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-envoy:${TAG} -f docker/Dockerfile.envoy .
else
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-envoy:${TAG} -f docker/Dockerfile.envoy_d .
endif

envoyd:
ifneq ($(VOLTHA_BUILD),docker)
	make -C envoy
	make -C envoy/go/envoyd
endif

go-builder:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-go-builder:${TAG} -f envoy/go/golang-builder/Dockerfile ./envoy/go/golang-builder

netconf:
ifneq ($(VOLTHA_BUILD),docker)
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-netconf:${TAG} -f docker/Dockerfile.netconf .
else
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-netconf:${TAG} -f docker/Dockerfile.netconf_d .
endif

netopeer:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-netopeer:${TAG} -f docker/Dockerfile.netopeer .

shovel:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-shovel:${TAG} -f docker/Dockerfile.shovel .

dashd:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-dashd:${TAG} -f docker/Dockerfile.dashd .

cli:
ifneq ($(VOLTHA_BUILD),docker)
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-cli:${TAG} -f docker/Dockerfile.cli .
else
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-cli:${TAG} -f docker/Dockerfile.cli_d .
endif

custom_cli: cli
ifeq ($(CUSTOM_CLI_LABEL),)
	docker build ${DOCKER_BUILD_ARGS} -t ${REGISTRY}${REPOSITORY}voltha-cli-custom:${TAG} -f docker/Dockerfile.cli_custom .
else
	docker build ${DOCKER_BUILD_ARGS} -t ${REGISTRY}${REPOSITORY}voltha-cli${CUSTOM_CLI_LABEL}:${TAG} -f docker/Dockerfile.cli_custom .
endif

portainer:
ifneq ($(VOLTHA_BUILD),docker)
	REGISTRY=${REGISTRY} REPOSITORY=${REPOSITORY} TAG=${TAG} portainer/buildPortainer.sh
else
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-portainer:${TAG} -f docker/Dockerfile.portainer_d .
endif

nginx:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-nginx:${TAG} -f docker/Dockerfile.nginx .

consul:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-consul:${TAG} -f docker/Dockerfile.consul .

grafana:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-grafana:${TAG} -f docker/Dockerfile.grafana .

onos:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-onos:${TAG} -f docker/Dockerfile.onos docker

unum:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-unum:${TAG} -f unum/Dockerfile ./unum

tester:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-tester:${TAG} -f docker/Dockerfile.tester docker

config-push:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-config-push:${TAG} -f docker/Dockerfile.configpush docker

opennms:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-opennms:${TAG} -f docker/Dockerfile.opennms .

logstash:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-logstash:${TAG} -f docker/Dockerfile.logstash .

ponsim:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-ponsim:${TAG} -f docker/Dockerfile.ponsim .

j2:
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-j2:${TAG} -f docker/Dockerfile.j2 docker

alarm-generator:
ifneq ($(VOLTHA_BUILD),docker)
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-alarm-generator:${TAG} -f docker/Dockerfile.alarm-generator .
else
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-alarm-generator:${TAG} -f docker/Dockerfile.alarm-generator_d .
endif

test_runner:
ifeq ($(VOLTHA_BUILD),docker)
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-test_runner:${TAG} -f docker/Dockerfile.test_runner .
endif

@MAKE_ENV := $(shell echo '$(.VARIABLES)' | awk -v RS=' ' '/^[a-zA-Z0-9]+$$/')
@SHELL_EXPORT := $(foreach v,$(MAKE_ENV),$(v)='$($(v))')
start:
	$(SHELL_EXPORT) STACK_TEMPLATE=./compose/voltha-stack.yml.j2 ./scripts/run-voltha.sh start
	
stop:
	./scripts/run-voltha.sh stop

tag: $(patsubst  %,%.tag,$(DOCKER_IMAGE_LIST))

push: tag $(patsubst  %,%.push,$(DOCKER_IMAGE_LIST))

pull: $(patsubst  %,%.pull,$(DOCKER_IMAGE_LIST))

%.tag:
	docker tag ${REGISTRY}${REPOSITORY}voltha-$(subst .tag,,$@):${TAG} ${TARGET_REGISTRY}${TARGET_REPOSITORY}voltha-$(subst .tag,,$@):${TARGET_TAG}

%.push:
	docker push ${TARGET_REGISTRY}${TARGET_REPOSITORY}voltha-$(subst .push,,$@):${TARGET_TAG}

%.pull:
	docker pull ${REGISTRY}${REPOSITORY}voltha-$(subst .pull,,$@):${TAG}

protoc:
ifeq ($(VOLTHA_BUILD),docker)
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-protoc:${TAG} -f docker/Dockerfile.protoc .
endif

protos:
ifneq ($(VOLTHA_BUILD),docker)
	make -C voltha/protos
	make -C ofagent/protos
	make -C netconf/protos
else
	docker build $(DOCKER_BUILD_ARGS) -t ${REGISTRY}${REPOSITORY}voltha-protos:${TAG} -f docker/Dockerfile.protos .
endif

install-protoc:
	make -C voltha/protos install-protoc

clean:
	find voltha -name '*.pyc' | xargs rm -f

distclean: clean
	rm -rf ${VENVDIR}

fetch:
	@bash -c ' \
		for i in $(FETCH_IMAGE_LIST); do \
			docker pull $$i; \
		done'

fetch-jenkins: fetch

purge-venv:
	rm -fr ${VENVDIR}

rebuild-venv: purge-venv venv

ifneq ($(VOLTHA_BUILD),docker)
venv: ${VENVDIR}/.built
else
venv:
endif

VENV_BIN ?= virtualenv
VENV_OPTS ?=

${VENVDIR}/.built:
	@ $(VENV_BIN) ${VENV_OPTS} ${VENVDIR}
	@ $(VENV_BIN) ${VENV_OPTS} --relocatable ${VENVDIR}
	@ . ${VENVDIR}/bin/activate && \
	    pip install --upgrade pip; \
	    if ! pip install -r requirements.txt; \
	    then \
	        echo "On MAC OS X, if the installation failed with an error \n'<openssl/opensslv.h>': file not found,"; \
	        echo "see the BUILD.md file for a workaround"; \
	    else \
	        uname -s > ${VENVDIR}/.built; \
	    fi
	@ $(VENV_BIN) ${VENV_OPTS} --relocatable ${VENVDIR}

ifneq ($(VOLTHA_BUILD),docker)
test: venv protos run-as-root-tests
	@ echo "Executing all tests"
	. ${VENVDIR}/bin/activate && \
	nosetests -s tests \
	--exclude-dir=./tests/itests/run_as_root/
else
test: protos test_runner run-as-root-tests
	docker run \
		-e VOLTHA_BUILD=docker \
		-e REGISTRY=${REGISTRY} \
		-e REPOSITORY=${REPOSITORY} \
		-e TAG=${TAG} \
		-e DOCKER_HOST_IP=${DOCKER_HOST_IP} \
		--rm --net=host -v /var/run/docker.sock:/var/run/docker.sock \
		${REGISTRY}${REPSOITORY}voltha-test_runner:${TAG} \
		nosetests -s tests --exclude-dir=./tests/itests/run_as_root/
endif

.PHONY: utest-adapters
TEST_ADAPTERS := $(shell find ./voltha/adapters -name test.mk)
TESTABLE_ADAPTERS:= $(patsubst %.mk,%_target,$(TEST_ADAPTERS))

%_target : %.mk
	@ echo Test Adapter \($<\)
	@ $(MAKE) -f $<

utest-adapters: $(TESTABLE_ADAPTERS)
	@ echo Completed utest of Testable Adapters


ifneq ($(VOLTHA_BUILD),docker)
utest: venv protos
	@ echo "Executing all unit tests"
	@ . ${VENVDIR}/bin/activate && nosetests ./tests/utests
	@ $(MAKE) utest-adapters
else
utest: protos test_runner
	docker run \
		-e VOLTHA_BUILD=docker \
		-e REGISTRY=${REGISTRY} \
		-e REPOSITORY=${REPOSITORY} \
		-e TAG=${TAG} \
		-e DOCKER_HOST_IP=${DOCKER_HOST_IP} \
		--rm --net=host -v /var/run/docker.sock:/var/run/docker.sock \
		${REGISTRY}${REPSOITORY}voltha-test_runner:${TAG} \
		bash -c \
		'. ${VENVDIR}/bin/activate && nosetests ./tests/utests; \
		$(MAKE) utest-adapters'
endif

COVERAGE_OPTS=--with-xcoverage --with-xunit --cover-package=voltha,common,ofagent --cover-html\
              --cover-html-dir=tmp/cover
ifneq ($(VOLTHA_BUILD),docker)
utest-with-coverage: venv protos
	@ echo "Executing all unit tests and producing coverage results"
	@ . ${VENVDIR}/bin/activate && nosetests $(COVERAGE_OPTS) ./tests/utests
	@ $(MAKE) utest-adapters
else
utest-with-coverage: protos test_runner
	@echo "Executing all unit tests and producing coverage results"
	docker run \
		-e VOLTHA_BUILD=docker \
		-e REGISTRY=${REGISTRY} \
		-e REPOSITORY=${REPOSITORY} \
		-e TAG=${TAG} \
		-e DOCKER_HOST_IP=${DOCKER_HOST_IP} \
		--rm --net=host -v /var/run/docker.sock:/var/run/docker.sock \
		${REGISTRY}${REPSOITORY}voltha-test_runner:${TAG} \
		bash -c \
		'nosetests ${COVERAGE_OPTS} ./tests/utests; \
		 $(MAKE) utest-adapters'
endif

ifneq ($(VOLTHA_BUILD),docker)
itest: venv run-as-root-tests
	@ echo "Executing all integration tests"
	. ${VENVDIR}/bin/activate && \
	rm -rf /tmp/fluentd/* && \
	REGISTRY=${REGISTRY} \
	REPOSITORY=${REPOSITORY} \
	TAG=${TAG} \
	DOCKER_HOST_IP=${DOCKER_HOST_IP} \
	nosetests -s  \
		tests/itests/docutests/build_md_test.py \
		--exclude-dir=./tests/utests/ \
		--exclude-dir=./tests/itests/run_as_root/
else
itest: protos test_runner
	@ echo "Executing all integration tests"
	docker run \
		-e VOLTHA_BUILD=docker \
		-e REGISTRY=${REGISTRY} \
		-e REPOSITORY=${REPOSITORY} \
		-e TAG=${TAG} \
		-e DOCKER_HOST_IP=${DOCKER_HOST_IP} \
		--rm --net=host -v /var/run/docker.sock:/var/run/docker.sock \
		${REGISTRY}${REPSOITORY}voltha-test_runner:${TAG} \
		nosetests -s  \
			tests/itests/docutests/build_md_test.py \
			--exclude-dir=./tests/utests/ \
			--exclude-dir=./tests/itests/run_as_root/
endif

ifneq ($(VOLTHA_BUILD),docker)
smoke-test: venv run-as-root-tests
	@ echo "Executing smoke tests"
	. ${VENVDIR}/bin/activate && \
	rm -rf /tmp/fluentd/* && \
	REGISTRY=${REGISTRY} \
	REPOSITORY=${REPOSITORY} \
	TAG=${TAG} \
	DOCKER_HOST_IP=${DOCKER_HOST_IP} \
	nosetests -s  \
	tests/itests/docutests/build_md_test.py:BuildMdTests.test_07_start_all_containers \
	--exclude-dir=./tests/itests/run_as_root/
else
smoke-test: protos test_runner run-as-root-tests
	@ echo "Executing smoke tests"
	docker run \
		-e VOLTHA_BUILD=docker \
		-e REGISTRY=${REGISTRY} \
		-e REPOSITORY=${REPOSITORY} \
		-e TAG=${TAG} \
		-e DOCKER_HOST_IP=${DOCKER_HOST_IP} \
		--rm --net=host -v /var/run/docker.sock:/var/run/docker.sock \
		${REGISTRY}${REPSOITORY}voltha-test_runner:${TAG} \
		nosetests -s  \
			tests/itests/docutests/build_md_test.py:BuildMdTests.test_07_start_all_containers \
			--exclude-dir=./tests/itests/run_as_root/
endif

ifneq ($(VOLTHA_BUILD),docker)
jenkins-test: venv
	@ echo "Executing jenkins smoke tests"
	. ${VENVDIR}/bin/activate && \
	rm -rf /tmp/fluentd/* && \
	REGISTRY=${REGISTRY} \
	REPOSITORY=${REPOSITORY} \
	TAG=${TAG} \
	DOCKER_HOST_IP=${DOCKER_HOST_IP} \
	nosetests -s  \
		tests/itests/docutests/build_md_test.py:BuildMdTests.test_07_start_all_containers \
		--exclude-dir=./tests/itests/run_as_root/
else
jenkins-test: protos test_runner
	@ echo "Executing jenkins smoke tests"
	@ echo "Starting VOLTHA as docker-compose services"
	docker run \
		-e REGISTRY=${REGISTRY} \
		-e REPOSITORY=${REPOSITORY} \
		-e TAG=${TAG} \
		-e DOCKER_HOST_IP=${DOCKER_HOST_IP} \
		--rm --net=host -v /var/run/docker.sock:/var/run/docker.sock \
		${REGISTRY}${REPSOITORY}voltha-test_runner:${TAG} \
		nosetests -s \
			tests/itests/docutests/build_md_test.py:BuildMdTests.test_07_start_all_containers \
			--exclude-dir=./tests/itests/run_as_root/
endif

ifneq ($(VOLTHA_BUILD),docker)
run-as-root-tests:
	docker run -i --rm -v /cord/incubator/voltha:/voltha --privileged ${REGISTRY}${REPOSITORY}voltha-base:${TAG} env PYTHONPATH=/voltha python /voltha/tests/itests/run_as_root/test_frameio.py
else
run-as-root-tests:
	docker run \
		-e VOLTHA_BUILD=docker \
		-e REGISTRY=${REGISTRY} \
		-e REPOSITORY=${REPOSITORY} \
		-e TAG=${TAG} \
		-e DOCKER_HOST_IP=${DOCKER_HOST_IP} \
		--rm --privileged \
		${REGISTRY}${REPOSITORY}voltha-test_runner:${TAG} \
		env PYTHONPATH=/work python tests/itests/run_as_root/test_frameio.py
endif

flake8: $(DIRS_FLAKE8)

# end file
