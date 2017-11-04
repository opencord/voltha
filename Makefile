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
GREEN := \033[32;1m
RED := \033[0;31m
YELLOW := \033[0;33m
WHITE := \033[1;37m
NC := \033[0m

ifeq ($(TAG),)
TAG := latest
endif

.PHONY: $(DIRS) $(DIRS_CLEAN) $(DIRS_FLAKE8) flake8 docker-base voltha ofagent podder netconf shovel onos dashd vcli portainer grafana nginx consul registrator envoy envoyd tools opennms logstash unum netopeer

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
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-base:${TAG} -f docker/Dockerfile.base .

voltha: voltha-adapters
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha:${TAG} -f docker/Dockerfile.voltha .

voltha-adapters: asfvolt16_olt

asfvolt16_olt:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-asfvolt16_olt:${TAG} -f docker/Dockerfile.asfvolt16_olt .

ofagent:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-ofagent:${TAG} -f docker/Dockerfile.ofagent .

podder:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-podder:${TAG} -f docker/Dockerfile.podder .

tools:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-tools:${TAG} -f docker/Dockerfile.tools .

fluentd:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-fluentd:${TAG} -f docker/Dockerfile.fluentd .

envoy:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-envoy:${TAG} -f docker/Dockerfile.envoy .

envoy-gobuilder:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-envoy-gobuilder:${TAG} -f envoy/go/golang-builder/Dockerfile envoy/go/golang-builder

envoyd: envoy-gobuilder
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-envoyd:${TAG} -f docker/Dockerfile.envoy .

netconf:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-netconf:${TAG} -f docker/Dockerfile.netconf .

netopeer:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-netopeer:${TAG} -f docker/Dockerfile.netopeer .

shovel:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-shovel:${TAG} -f docker/Dockerfile.shovel .

dashd:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-dashd:${TAG} -f docker/Dockerfile.dashd .

vcli:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-cli:${TAG} -f docker/Dockerfile.cli .

portainer:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-portainer:${TAG} -f docker/Dockerfile.portainer .

nginx:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-nginx:${TAG} -f docker/Dockerfile.nginx .

consul:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-consul:${TAG} -f docker/Dockerfile.consul .

registrator:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-registrator:${TAG} -f docker/Dockerfile.registrator .

grafana:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-grafana:${TAG} -f docker/Dockerfile.grafana .

onos:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-onos:${TAG} -f docker/Dockerfile.onos docker

unum:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-unum:${TAG} -f unum/Dockerfile ./unum

tester:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-tester:${TAG} -f docker/Dockerfile.tester docker

config-push:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-config-push:${TAG} -f docker/Dockerfile.configpush docker

opennms:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-opennms:${TAG} -f docker/Dockerfile.opennms .

logstash:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-logstash:${TAG} -f docker/Dockerfile.logstash .

protoc:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-protoc:${TAG} -f docker/Dockerfile.protoc .

protos:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-protos:${TAG} -f docker/Dockerfile.protos .

protos_local:
	make -C voltha/protos
	VOLTHA_BASE=$(shell pwd) make -C ofagent/protos
	VOLTHA_BASE=$(shell pwd) make -C netconf/protos

testrunner:
	docker build ${DOCKER_CACHE} --rm --force-rm -t opencord/voltha-testrunner:${TAG} -f docker/Dockerfile.testrunner .

publish:
	@ for i in $(shell grep "docker build" Makefile | awk '{print $$7}' | grep "opencord/voltha"); do docker push $$i; done

publishas:
	@ for i in $(shell grep "docker build" Makefile | awk '{print $$7}' | grep "opencord/voltha"); do docker tag $$i:latest $$i:$${TAG:-"latest"}; docker push $$i:$${TAG:-"latest"}; done

venv:
	@ echo "${WHITE}We don't need no stinking virtual environment${NC}"

requires-swarm:
	@ echo "${RED}Docker Swarm Mode required for tests${NC}"
	@ echo "${WHITE}A Docker Swarm is required to run the integration tests${NC}"
	@ echo "${WHITE}A single node swarm can be created by executing the following${NC}"
	@ echo "${WHITE}Command:${NC}"
	@ echo ""
	@ echo "${WHITE}     docker swarm init${NC}"
	@ echo ""
	@ exit 1

test: #protos_local
	@ echo "Executing all tests"
	@ test \! -z "$(shell docker info -f '{{.Swarm.NodeID}}')" || make requires-swarm
	@ echo "Starting VOLTHA ..."
	@ ./install/voltha-swarm-start.sh
	@ bash -c ' \
		RETRIES=10; \
		COLOR="${WHITE}"; \
		while [ $$RETRIES -gt 0 ]; do \
			SVC=$$(docker service ls --format "{{.Name}}/{{.Replicas}}" | grep "^voltha\|^consul\|^kafka\|^fluentd" | awk -F/ "{if ( \$$2 != \$$3 ) { print \$$1; exit 1 }}"); \
			if [ $$? -eq 0 ]; then \
				echo -e "${GREEN}VOLTHA Started${NC}"; \
				exit 0; \
			fi; \
			RETRIES=$$(expr $$RETRIES - 1); \
			if [ $$RETRIES -lt 3 ]; then \
				COLOR="${RED}"; \
			elif [ $$RETRIES -lt 7 ]; then \
				COLOR="${YELLOW}"; \
			fi; \
			echo -e "$${COLOR}Waiting for VOLTHA to start ...${NC}"; \
			sleep 5; \
		done; \
		echo -e "${RED}Unable to start VOLTHA${NC}"; \
		echo -e "Service \"${WHITE}$$SVC${NC}\" not started"; \
		./install/voltha-swarm-stop.sh -z; \
		exit 1; \
		'
	@ echo "Stopping VOLTHA ..."
	@ ./install/voltha-swarm-stop.sh -z
	@ echo "${GREEN}COMPLETE${NC}"
#	@ echo "${RED}THESE DO NOT WORK IN STANDARD BUILD${NC}"
#	nosetests -s tests --exclude-dir=./tests/itests/run_as_root/
#	docker run -ti --rm -w /voltha \
#		-e PYTHONPATH=/voltha/voltha:/voltha/voltha/protos/third_party \
#		opencord/voltha-testrunner \
#		nosetests -s tests --exclude-dir=./tests/itests/run_as_root/

utest: protoc protos testrunner
	@ echo "Executing all unit tests"
	for d in $$(find ./tests/utests -type d|sort -nr); do \
		echo $$d:; \
		docker run --rm -w /voltha \
		-e PYTHONPATH=/voltha/voltha:/voltha/ofagent \
		opencord/voltha-testrunner:${TAG} \
		nosetests $$d; \
		done

utest-with-coverage: protoc protos testrunner
	@ echo "Executing all unit tests and producing coverage results"
	for d in $$(find ./tests/utests -type d|sort -nr); do \
                echo $$d:; \
                docker run --rm -w /voltha \
                -e PYTHONPATH=/voltha/voltha:/voltha/ofagent \
		opencord/voltha-testrunner:${TAG} \
		nosetests --with-xcoverage --with-xunit --cover-package=voltha,common,ofagent $$d; \
                done

itest: protoc protos testrunner run-as-root-tests
	@ echo "Executing all integration tests"
	@ echo "${RED}THESE DO NOT WORK IN STANDARD BUILD${NC}"
	docker run -ti --rm -w /voltha \
                -e PYTHONPATH=/voltha/voltha:/voltha/ofagent \
                opencord/voltha-testrunner \
                nosetests -s tests/itests/docutests/build_md_test.py \
		--exclude-dir=./tests/utests/ \
		--exclude-dir=./tests/itests/run_as_root/
#	. ${VENVDIR}/bin/activate && \
#	nosetests -s  \
#	tests/itests/docutests/build_md_test.py \
#	--exclude-dir=./tests/utests/ \
#	--exclude-dir=./tests/itests/run_as_root/

smoke-test: venv run-as-root-tests
	@ echo "Executing smoke tests"
	@ echo "${RED}TEMPORARILY DISABLED${NC}"
#	. ${VENVDIR}/bin/activate && \
#	nosetests -s  \
#	tests/itests/docutests/build_md_test.py:BuildMdTests.test_07_start_all_containers \
#	--exclude-dir=./tests/itests/run_as_root/

jenkins-test: venv
	@ echo "Executing jenkins smoke tests"
	@ echo "${RED}TEMPORARILY DISABLED${NC}"
#	. ${VENVDIR}/bin/activate && \
#	nosetests -s  \
#	tests/itests/docutests/build_md_test.py:BuildMdTests.test_07_start_all_containers \
#	--exclude-dir=./tests/itests/run_as_root/


run-as-root-tests:
	docker run -ti --rm -v $(shell pwd):/voltha --privileged opencord/voltha-base env PYTHONPATH=/voltha python /voltha/tests/itests/run_as_root/test_frameio.py

flake8: $(DIRS_FLAKE8)

clean:
	VOLTHA_BASE=$(shell pwd) make -C voltha/protos clean
	VOLTHA_BASE=$(shell pwd) make -C ofagent/protos clean
	VOLTHA_BASE=$(shell pwd) make -C netconf/protos clean


# end file
