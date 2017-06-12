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

include setup.mk

VENVDIR := venv-$(shell uname -s | tr '[:upper:]' '[:lower:]')

.PHONY: $(DIRS) $(DIRS_CLEAN) $(DIRS_FLAKE8) flake8 docker-base voltha chameleon ofagent podder netconf shovel onos dashd vcli portainer grafana nginx consul registrator

# This should to be the first and default target in this Makefile
help:
	@echo "Usage: make [<target>]"
	@echo "where available targets are:"
	@echo
	@echo "build        : Build the Voltha protos and docker images.\n\
               If this is the first time you are building, choose \"make build\" option."
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
	@echo "chameleon    : Build the chameleon docker container"
	@echo "ofagent      : Build the ofagent docker container"
	@echo "podder       : Build the podder docker container"
	@echo "netconf      : Build the netconf docker container"
	@echo "shovel       : Build the shovel docker container"
	@echo "onos         : Build the onos docker container"
	@echo "dashd        : Build the dashd docker container"
	@echo "vcli         : Build the vcli docker container"
	@echo "portainer    : Build the portainer docker container"
	@echo "grafana      : Build the grafana docker container"
	@echo "nginx        : Build the nginx docker container"
	@echo "consul       : Build the consul docker container"
	@echo "registrator  : Build the registrator docker container"
	@echo

## New directories can be added here
DIRS:=\
voltha \
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

containers: docker-base voltha chameleon ofagent podder netconf shovel onos tester config-push dashd vcli portainer grafana nginx consul registrator

docker-base:
	docker build -t cord/voltha-base -f docker/Dockerfile.base .

voltha: voltha-adapters
	docker build -t cord/voltha -f docker/Dockerfile.voltha .

voltha-adapters:
	make -C voltha/adapters/asfvolt16_olt

chameleon:
	mkdir tmp.chameleon
	cp -R chameleon/* tmp.chameleon
	docker build -t cord/chameleon -f docker/Dockerfile.chameleon .
	rm -rf tmp.chameleon

ofagent:
	docker build -t cord/ofagent -f docker/Dockerfile.ofagent .

podder:
	docker build -t cord/podder -f docker/Dockerfile.podder .

netconf:
	docker build -t cord/netconf -f docker/Dockerfile.netconf .

netopeer:
	docker build -t cord/netopeer -f docker/Dockerfile.netopeer .

shovel:
	docker build -t cord/shovel -f docker/Dockerfile.shovel .

dashd:
	docker build -t cord/dashd -f docker/Dockerfile.dashd .

vcli:
	docker build -t cord/vcli -f docker/Dockerfile.cli .

portainer:
	portainer/buildPortainer.sh

nginx:
	docker build -t voltha/nginx -f docker/Dockerfile.nginx .

consul:
	docker build -t voltha/consul -f docker/Dockerfile.consul .

registrator:
	docker build -t voltha/registrator -f docker/Dockerfile.registrator .

grafana:
	docker build -t voltha/grafana -f docker/Dockerfile.grafana .

onos:
	docker build -t cord/onos -f docker/Dockerfile.onos docker

tester:
	docker build -t cord/tester -f docker/Dockerfile.tester docker

config-push:
	docker build -t cord/config-push -f docker/Dockerfile.configpush docker	


protos:
	make -C voltha/protos
	make -C chameleon/protos
	make -C ofagent/protos
	make -C netconf/protos

install-protoc:
	make -C voltha/protos install-protoc

clean:
	find voltha -name '*.pyc' | xargs rm -f

distclean: clean
	rm -rf ${VENVDIR}

fetch:
	docker pull consul:latest
	docker pull fluent/fluentd:latest
	docker pull gliderlabs/registrator:latest
	docker pull ubuntu:xenial
	docker pull wurstmeister/kafka:latest
	docker pull wurstmeister/zookeeper:latest
	docker pull nginx:latest
	docker pull portainer/portainer:latest

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
	    for d in $$(find ./tests/utests -depth -type d); do echo $$d:; nosetests $$d; done

utest-with-coverage: venv protos
	@ echo "Executing all unit tests and producing coverage results"
	. ${VENVDIR}/bin/activate && \
        for d in $$(find ./tests/utests -depth -type d); do echo $$d:; \
	nosetests --with-xcoverage --with-xunit --cover-package=voltha,common,ofagent,chameleon $$d; done

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


run-as-root-tests:
	docker run -i --rm -v /cord/incubator/voltha:/voltha --privileged cord/voltha-base env PYTHONPATH=/voltha python /voltha/tests/itests/run_as_root/test_frameio.py

flake8: $(DIRS_FLAKE8)

# end file
