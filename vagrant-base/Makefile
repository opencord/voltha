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

PROTO_FILES := $(wildcard *.proto) $(wildcard third_party/google/api/*proto)
PROTO_PB2_FILES := $(foreach f,$(PROTO_FILES),$(subst .proto,_pb2.py,$(f)))
PROTO_DESC_FILES := $(foreach f,$(PROTO_FILES),$(subst .proto,.desc,$(f)))

PROTOC_PREFIX := /usr/local
PROTOC_LIBDIR := $(PROTOC_PREFIX)/lib

PROTOC := $(PROTOC_PREFIX)/bin/protoc

PROTOC_VERSION := "3.3.0"
PROTOC_DOWNLOAD_PREFIX := "https://github.com/google/protobuf/releases/download"
PROTOC_DIR := protobuf-$(PROTOC_VERSION)
PROTOC_TARBALL := protobuf-python-$(PROTOC_VERSION).tar.gz
PROTOC_DOWNLOAD_URI := $(PROTOC_DOWNLOAD_PREFIX)/v$(PROTOC_VERSION)/$(PROTOC_TARBALL)
PROTOC_BUILD_TMP_DIR := "/tmp/protobuf-build-$(shell uname -s | tr '[:upper:]' '[:lower:]')"

TOKEN_FILE := vagrant-token
TOKEN := `cat $(TOKEN_FILE)`

VAGRANT_VOLTHA_BASE_INFO="$(shell vagrant box list | grep voltha-base | tail -n 1 | cut -d ',' -f 2 | cut -d ' ' -f 2)"
CURRENT_VERSION=`echo $(VAGRANT_VOLTHA_BASE_INFO) | cut -d ')' -f 1`
CURRENT_VERSION_DYNAMIC=`echo $$(vagrant box list | grep voltha-base | tail -n 1 | cut -d ',' -f 2 | cut -d ' ' -f 2) | cut -d ')' -f 1`
TIME := $(shell date +"%y%m%d.%H%M%S.0")
VERSION := `echo $(TIME)`
VERSION_DYNAMIC := `echo $$(date +"%y%m%d.%H%M%S.0")`

default: build

build: add-update-voltha-base build-core

print-info:
	@echo "TOKEN ---------------------->  "$(TOKEN)
	@echo "TIME ----------------------->  "$(TIME)
	@echo "VERSION -------------------->  "$(VERSION)
	@echo "VERSION_DYNAMIC ------------>  "$(VERSION_DYNAMIC)
	@echo "CURRENT_VERSION ------------>  "$(CURRENT_VERSION)
	@echo "CURRENT_VERSION_DYNAMIC ---->  "$(CURRENT_VERSION_DYNAMIC)

help:
	@echo
	@echo "Usage: make [<target>] [VERSION='X.X.X']"
	@echo "where available targets are:"
	@echo
	@echo "help                 : Print this help"
	@echo "build                : Build the Voltha-base vagrant box and upload it to Vagrant Cloud (default target)"
	@echo "build-core           : Execute the main tasks to build theVoltha-base vagrant box and upload it to Vagrant Cloud (default target)"
	@echo "clean                : Stop/Remove the Voltha-base virtual machine"
	@echo "start-message        : Print Voltha-base banner"
	@echo "update-voltha-base   : Update the Voltha-base (voltha/voltha-base) box to the latest version"
	@echo "test-voltha-base     : Test the Voltha-base vagrant image"
	@echo "run-voltha-base      : Run the Voltha-base (vagrant up)"
	@echo "package-voltha-base  : Package the Voltha-base vagrant image to a .box package"
	@echo "create-version       : Create a new version on Vagrant Cloud"
	@echo "create-provider      : Create & assign an provider to a version on Vagrant Cloud"
	@echo "upload-package       : Upload a package.box file to Vagrant Cloud and assign it to a version and provider"
	@echo "release-version      : Release a verson as the available version of the Voltha-base on Vagrant Cloud"
	@echo

$(PROTOC):
	@echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	@echo "It looks like you don't have protocol buffer tools installed."
	@echo "To install the protocol buffer toolchain, you can run:"
	@echo "    make install-protoc"
	@echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

install-protoc: $(PROTOC)
	@echo "Downloading and installing protocol buffer support."
	@echo "Installation will require sodo priviledges"
	@echo "This will take a few minutes."
	mkdir -p $(PROTOC_BUILD_TMP_DIR)
	@echo "We ask for sudo credentials now so we can install at the end"; \
	sudo echo "Thanks"; \
	    cd $(PROTOC_BUILD_TMP_DIR); \
	    wget $(PROTOC_DOWNLOAD_URI); \
	    tar xzvf $(PROTOC_TARBALL); \
	    cd $(PROTOC_DIR); \
	    ./configure --prefix=$(PROTOC_PREFIX); \
	    make; \
	    sudo make install

build-core: banner run-voltha-base package-voltha-base create-version create-provider upload-package release-version clean update-voltha-base

add-update-voltha-base:
	@echo "Adding/Updating voltha-base vagrant box"; \
	vagrant box update --box voltha/voltha-base || vagrant box add voltha/voltha-base

update-voltha-base:
	@echo "Updating voltha-base vagrant box"; \
	vagrant box update --box voltha/voltha-base

add-voltha-base:
	@echo "Adding voltha-base vagrant box"; \
	vagrant box add voltha/voltha-base

remove-voltha-base:
	@echo "Removing all the voltha-base vagrant box versions"; \
	vagrant box remove voltha/voltha-base --all

banner:
	@echo
	@echo "|------------------------------------------------------------------------|"
	@echo "|  _    ______  __  ________  ______           ____   ______ _____ ____  |"
	@echo "| | |  / / __ \/ / /_  __/ / / / /| |         / ___ \/ ___  / ____/ ___| |"
	@echo "| | | / / / / / /   / / / /_/ / /_| |  ___   / /__/ / /__/ / /___  /___  |"
	@echo "| | |/ / /_/ / /___/ / / __  / ___  | |___| / /__/ / ___   \__  / /____  |"
	@echo "| |___/\____/_____/_/ /_/ /_/_/  |__|      /______/_/  /_/\____/_______| |"
	@echo "|                                                                        |"
	@echo "|------------------------------------------------------------------------|"
	@echo "|                MAKING & UPLOADING VOLTHA-BASE VAGRANT BOX              |"
	@echo "|------------------------------------------------------------------------|"
	@echo
	@echo "VERSION ----> $(VERSION)"

test-voltha-base:
	@echo "Testing the recently created voltha-base"; \
	vagrant up; \
		./test_script.sh

run-voltha-base:
	@echo "Running voltha-base vagrant box"
	@echo "Stopping any running voltha-base vagrant box"; \
	vagrant halt; \
		vagrant destroy -f; \
		vagrant up

package-voltha-base:
	@echo "Packaging vagrant VM"
	@echo "Removing previous package.box, if exists"; \
	rm package.box; \
		vagrant package

create-version:
	@echo "Creating a new version on Vagrant Cloud"
	@echo "Version: $(VERSION)"
	curl https://atlas.hashicorp.com/api/v1/box/voltha/voltha-base/versions \
		-X POST -H "X-Atlas-Token: $(TOKEN)" \
		-d version[version]=$(VERSION) \
		-d version[description]='This is the new version' | jq

create-provider:
	@echo "Creating a provider for the new version on Vagrant Cloud"
	@echo "We have virtualbox as provider"; \
	curl https://atlas.hashicorp.com/api/v1/box/voltha/voltha-base/version/$(VERSION)/providers \
		-X POST -H "X-Atlas-Token: $(TOKEN)" \
		-d provider[name]='virtualbox' | jq

upload-package:
	@echo "Uploading the new package.box on Vagrant Cloud"; \
	echo $(VERSION); \
		url=$(shell curl https://atlas.hashicorp.com/api/v1/box/voltha/voltha-base/version/$(VERSION)/provider/virtualbox/upload?access_token=$(TOKEN) | jq '.["upload_path"]'); \
			echo $$url; \
			echo 'WAIT FOR IT....'; \
			curl -X PUT --upload-file package.box $$url

release-version:
	@echo "Releasing the version, so the box will be accessible to all users"; \
	curl https://atlas.hashicorp.com/api/v1/box/voltha/voltha-base/version/$(VERSION)/release \
		-X PUT -H "X-Atlas-Token: $(TOKEN)" | jq

clean:
	@echo "Cleaning up the voltha-base vagrant image"; \
	vagrant halt; \
		vagrant destroy -f
