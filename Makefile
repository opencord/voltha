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
#$(error To get started, please source the env.sh file)
endif

include setup.mk

VENVDIR := venv-$(shell uname -s | tr '[:upper:]' '[:lower:]')

.PHONY: $(DIRS) $(DIRS_CLEAN) $(DIRS_FLAKE8) flake8 docker-base voltha ofagent podder netconf shovel onos dashd vcli portainer grafana nginx consul registrator envoy envoyd tools opennms logstash unum

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
	@echo "unum         : Build the unum docker container"
	@echo


build: protos containers

production: protos prod-containers

jenkins : protos jenkins-containers

jenkins-containers: docker-base voltha ofagent netconf consul registrator unum

prod-containers: docker-base voltha ofagent netconf shovel dashd vcli grafana consul tools envoyd envoy fluentd unum

containers: docker-base voltha ofagent podder netconf shovel onos tester config-push dashd vcli portainer grafana nginx consul registrator tools envoyd envoy fluentd unum

docker-base:
	docker build --rm --force-rm -t opencord/voltha-base -f docker/Dockerfile.base .

voltha: voltha-adapters
	docker build --rm --force-rm -t opencord/voltha -f docker/Dockerfile.voltha .

voltha-adapters: asfvolt16_olt

asfvolt16_olt:
	docker build --rm --force-rm -t opencord/voltha-asfvolt16_olt -f docker/Dockerfile.asfvolt16_olt .

ofagent:
	docker build --rm --force-rm -t opencord/voltha-ofagent -f docker/Dockerfile.ofagent .

podder:
	docker build --rm --force-rm -t opencord/voltha-podder -f docker/Dockerfile.podder .

tools:
	docker build --rm --force-rm -t opencord/voltha-tools -f docker/Dockerfile.tools .

fluentd:
	docker build --rm --force-rm -t opencord/voltha-fluentd -f docker/Dockerfile.fluentd .

envoy:
	docker build --rm --force-rm -t opencord/voltha-envoy -f docker/Dockerfile.envoy .

envoy-gobuilder:
	docker build --rm --force-rm -t opencord/voltha-envoy-gobuilder -f envoy/go/golang-builder/Dockerfile envoy/go/golang-builder

envoyd: envoy-gobuilder
	docker build --rm --force-rm -t opencord/voltha-envoyd -f docker/Dockerfile.envoy .

netconf:
	docker build --rm --force-rm -t opencord/voltha-netconf -f docker/Dockerfile.netconf .

netopeer:
	docker build --rm --force-rm -t opencord/voltha-netopeer -f docker/Dockerfile.netopeer .

shovel:
	docker build --rm --force-rm -t opencord/voltha-shovel -f docker/Dockerfile.shovel .

dashd:
	docker build --rm --force-rm -t opencord/voltha-dashd -f docker/Dockerfile.dashd .

vcli:
	docker build --rm --force-rm -t opencord/voltha-cli -f docker/Dockerfile.cli .

portainer:
	docker build --rm --force-rm -t opencord/voltha-portainer -f docker/Dockerfile.portainer .

nginx:
	docker build --rm --force-rm -t voltha/nginx -f docker/Dockerfile.nginx .

consul:
	docker build --rm --force-rm -t opencord/voltha-consul -f docker/Dockerfile.consul .

registrator:
	docker build --rm --force-rm -t voltha/registrator -f docker/Dockerfile.registrator .

grafana:
	docker build --rm --force-rm -t opencord/voltha-grafana -f docker/Dockerfile.grafana .

onos:
	docker build --rm --force-rm -t opencord/voltha-onos -f docker/Dockerfile.onos docker

unum:
	docker build --rm --force-rm -t opencord/voltha-unum -f unum/Dockerfile ./unum

tester:
	docker build --rm --force-rm -t cord/tester -f docker/Dockerfile.tester docker

config-push:
	docker build --rm --force-rm -t cord/config-push -f docker/Dockerfile.configpush docker	

opennms:
	docker build --rm --force-rm -t opencord/voltha-opennms -f docker/Dockerfile.opennms .

logstash:
	docker build --rm --force-rm -t opencord/voltha-logstash -f docker/Dockerfile.logstash .

protoc:
	docker build --rm --force-rm -t opencord/voltha-protoc -f docker/Dockerfile.protoc .

protos:
	docker build --rm --force-rm -t opencord/voltha-protos -f docker/Dockerfile.protos .

protos_local:
	make -C voltha/protos

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
	docker run -i --rm -v /cord/incubator/voltha:/voltha --privileged cord/voltha-base env PYTHONPATH=/voltha python /voltha/tests/itests/run_as_root/test_frameio.py

flake8: $(DIRS_FLAKE8)

# end file
