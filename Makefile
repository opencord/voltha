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

ifeq ($(VOLTHA_BASE)_set,_set)
$(error To get started, please source the env.sh file)
endif

ifeq ($(TAG),)
TAG := latest
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
DOCKER_BUILD_ARGS = --build-arg TAG=$(TAG) $(DOCKER_PROXY_ARGS) $(DOCKER_CACHE_ARG) --rm --force-rm $(DOCKER_BUILD_EXTRA_ARGS)

VENVDIR := venv-$(shell uname -s | tr '[:upper:]' '[:lower:]')

.PHONY: $(DIRS) $(DIRS_CLEAN) $(DIRS_FLAKE8) flake8 docker-base voltha ofagent netconf shovel onos dashd cli portainer grafana nginx consul envoy golang envoyd tools opennms logstash unum start stop

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
	@echo "protos       : Compile all grpc/protobuf files"
	@echo "rebuild-venv : Rebuild local Python virtualenv from scratch"
	@echo "venv         : Build local Python virtualenv if did not exist yet"
	@echo "utest        : Run all unit tests"
	@echo "itest        : Run all integration tests"
	@echo "containers   : Build all the docker containers"
	@echo "docker-base  : Build the base docker container used by all other dockers"
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
	@echo "j2           : Build the Jinja2 template container"
	@echo "start        : Start VOLTHA on the current system"
	@echo "stop         : Stop VOLTHA on the current system"
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

build: protos containers

production: protos prod-containers

jenkins : protos jenkins-containers

jenkins-containers: docker-base voltha ofagent netconf consul unum j2

prod-containers: docker-base voltha ofagent netconf shovel dashd cli grafana consul tools golang envoyd envoy fluentd unum j2

containers: docker-base voltha ofagent netconf shovel onos tester config-push dashd cli portainer grafana nginx consul tools golang envoyd envoy fluentd unum j2

docker-base:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/voltha-base:$(TAG) -f docker/Dockerfile.base .

voltha: voltha-adapters
	docker build $(DOCKER_BUILD_ARGS) -t voltha/voltha:$(TAG) -f docker/Dockerfile.voltha .

voltha-adapters:
	make -C voltha/adapters/asfvolt16_olt

ofagent:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/ofagent:$(TAG) -f docker/Dockerfile.ofagent .

tools:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/tools:$(TAG) -f docker/Dockerfile.tools .

fluentd:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/fluentd:$(TAG) -f docker/Dockerfile.fluentd .

envoy:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/envoy:$(TAG) -f docker/Dockerfile.envoy .

envoyd:
	make -C envoy
	make -C envoy/go/envoyd

golang:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/go-builder:$(TAG) -f envoy/go/golang-builder/Dockerfile ./envoy/go/golang-builder

netconf:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/netconf:$(TAG) -f docker/Dockerfile.netconf .

netopeer:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/netopeer:$(TAG) -f docker/Dockerfile.netopeer .

shovel:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/shovel:$(TAG) -f docker/Dockerfile.shovel .

dashd:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/dashd:$(TAG) -f docker/Dockerfile.dashd .

cli:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/cli:$(TAG) -f docker/Dockerfile.cli .

portainer:
	portainer/buildPortainer.sh

nginx:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/nginx:$(TAG) -f docker/Dockerfile.nginx .

consul:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/consul:$(TAG) -f docker/Dockerfile.consul .

grafana:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/grafana:$(TAG) -f docker/Dockerfile.grafana .

onos:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/onos:$(TAG) -f docker/Dockerfile.onos docker

unum:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/unum:$(TAG) -f unum/Dockerfile ./unum

tester:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/tester:$(TAG) -f docker/Dockerfile.tester docker

config-push:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/config-push:$(TAG) -f docker/Dockerfile.configpush docker

opennms:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/opennms:$(TAG) -f docker/Dockerfile.opennms .

logstash:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/logstash:$(TAG) -f docker/Dockerfile.logstash .

j2:
	docker build $(DOCKER_BUILD_ARGS) -t voltha/j2:$(TAG) -f docker/Dockerfile.j2 docker

start:
	bash -c 'echo $$VOLTHA_LOGS &&  TMP_STACK_FILE=$$(mktemp -u) && \
		echo $$TMP_STACK_FILE && \
		SWARM_MANAGER_COUNT=$$(docker node ls | grep Ready | egrep "(Leader)|(Reachable)" | wc -l | sed -e "s/ //g") && \
	        cat ./compose/voltha-stack.yml.j2 2>&1 | docker run -e RADIUS_ROOT=$$RADIUS_ROOT -e CONSUL_ROOT=$$CONSUL_ROOT -e VOLTHA_LOGS=$$VOLTHA_LOGS -e SWARM_MANAGER_COUNT=$$SWARM_MANAGER_COUNT --rm -i voltha/j2 - 2>&1 > $$TMP_STACK_FILE && \
	        docker stack deploy -c $$TMP_STACK_FILE voltha && \
	        rm -f $$TMP_STACK_FILE'

stop:
	docker stack rm voltha

protos:
	make -C voltha/protos
	make -C ofagent/protos
	make -C netconf/protos

install-protoc:
	make -C voltha/protos install-protoc

clean:
	find voltha -name '*.pyc' | xargs rm -f

distclean: clean
	rm -rf ${VENVDIR}


fetch-jenkins:
	docker pull consul:0.9.2
	docker pull fluent/fluentd:v0.14.23.rc1
	docker pull ubuntu:xenial
	docker pull wurstmeister/kafka:1.0.0
	docker pull zookeeper:3.4.11
fetch:
	docker pull consul:0.9.2
	docker pull fluent/fluentd:v0.14.23.rc1
	docker pull ubuntu:xenial
	docker pull wurstmeister/kafka:1.0.0
	docker pull zookeeper:3.4.11
	docker pull portainer/portainer:1.15.2
	docker pull lyft/envoy:29361deae91575a1d46c7a21e913f19e75622ebe
	docker pull registry:2
	docker pull kamon/grafana_graphite:3.0

purge-venv:
	rm -fr ${VENVDIR}

rebuild-venv: purge-venv venv

venv: ${VENVDIR}/.built

${VENVDIR}/.built:
	@ virtualenv ${VENVDIR}
	@ . ${VENVDIR}/bin/activate && \
	    pip install --upgrade pip; \
	    if ! pip install -r requirements.txt; \
	    then \
	        echo "On MAC OS X, if the installation failed with an error \n'<openssl/opensslv.h>': file not found,"; \
	        echo "see the BUILD.md file for a workaround"; \
	    else \
	        uname -s > ${VENVDIR}/.built; \
	    fi

test: venv protos run-as-root-tests
	@ echo "Executing all tests"
	. ${VENVDIR}/bin/activate && \
	nosetests -s tests \
	--exclude-dir=./tests/itests/run_as_root/

utest: venv protos
	@ echo "Executing all unit tests"
	. ${VENVDIR}/bin/activate && \
	    for d in $$(find ./tests/utests -type d|sort -nr); do echo $$d:; nosetests $$d; done

utest-with-coverage: venv protos
	@ echo "Executing all unit tests and producing coverage results"
	. ${VENVDIR}/bin/activate && \
        for d in $$(find ./tests/utests -type d|sort -nr); do echo $$d:; \
	nosetests --with-xcoverage --with-xunit --cover-package=voltha,common,ofagent $$d; done

itest: venv run-as-root-tests
	@ echo "Executing all integration tests"
	. ${VENVDIR}/bin/activate && \
	nosetests -s  \
	tests/itests/docutests/build_md_test.py \
	--exclude-dir=./tests/utests/ \
	--exclude-dir=./tests/itests/run_as_root/

smoke-test: venv run-as-root-tests
	@ echo "Executing smoke tests"
	. ${VENVDIR}/bin/activate && \
	nosetests -s  \
	tests/itests/docutests/build_md_test.py:BuildMdTests.test_07_start_all_containers \
	--exclude-dir=./tests/itests/run_as_root/

jenkins-test: venv
	@ echo "Executing jenkins smoke tests"
	. ${VENVDIR}/bin/activate && \
	nosetests -s  \
	tests/itests/docutests/build_md_test.py:BuildMdTests.test_07_start_all_containers \
	--exclude-dir=./tests/itests/run_as_root/


run-as-root-tests:
	docker run -i --rm -v /cord/incubator/voltha:/voltha --privileged voltha/voltha-base env PYTHONPATH=/voltha python /voltha/tests/itests/run_as_root/test_frameio.py

flake8: $(DIRS_FLAKE8)

# end file
