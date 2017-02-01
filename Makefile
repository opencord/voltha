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

.PHONY: $(DIRS) $(DIRS_CLEAN) $(DIRS_FLAKE8) flake8 docker-base voltha chameleon ofagent podder netconf shovel onos

default: build

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

help:
	@echo "Usage: make [<target>]"
	@echo "where available targets are:"
	@echo
	@echo "build        : Build the Voltha docker images (default target)"
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
	@echo

build: protos containers

containers: docker-base voltha chameleon ofagent podder netconf shovel onos tester

docker-base:
	docker build -t cord/voltha-base -f docker/Dockerfile.base .

voltha:
	docker build -t cord/voltha -f docker/Dockerfile.voltha .

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

shovel:
	docker build -t cord/shovel -f docker/Dockerfile.shovel .

onos:
	docker build -t cord/onos -f docker/Dockerfile.onos docker

tester:
	docker build -t cord/tester -f docker/Dockerfile.tester docker

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
	docker run -i --rm -v /voltha:/voltha --privileged cord/voltha-base env PYTHONPATH=/voltha python /voltha/tests/itests/run_as_root/test_frameio.py

flake8: $(DIRS_FLAKE8)

# end file
