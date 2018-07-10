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

# VOLTHA pki makefile
# Configuration is also given in voltha.cnf

SHELL = bash -eu -o pipefail

# parameters

KEY_SIZE ?= 2048
EXPIRATION_DAYS ?= 366


# utility/validation targets

help:
	@echo "Usually you want to run 'make voltha.crt'"

validate:
	 openssl verify -verbose -purpose sslserver -CAfile voltha-CA.pem voltha.crt

printca: voltha-CA.pem
	openssl x509 -in voltha-CA.pem -text -noout

printkey: voltha.key
	openssl rsa -in voltha.key -check

printcsr: voltha.csr
	openssl req -in voltha.csr -text -noout -verify

printcrt: voltha.crt
	openssl x509 -in voltha.crt -text -noout

clean:
	rm -rf root_ca voltha-CA.pem voltha.key voltha.csr voltha.crt

# CA creation

root_ca:
	mkdir -p root_ca/private root_ca/newcerts
	chmod 700 root_ca/private
	echo 1000 > root_ca/serial
	touch root_ca/index.txt

root_ca/private/ca_root_phrase: root_ca
	@echo "TestingVOLTHARootCAPassPhrase" > root_ca/private/ca_root_phrase

root_ca/private/ca_key.pem: root_ca root_ca/private/ca_root_phrase
	@echo "## Creating CA private key"
	openssl genrsa -aes256 \
	  -passout file:root_ca/private/ca_root_phrase \
	  -out root_ca/private/ca_key.pem $(KEY_SIZE)

voltha-CA.pem: voltha.cnf root_ca/private/ca_key.pem
	@echo "## Creating self-signed CA public key: voltha-CA.pem"
	openssl req -config voltha.cnf \
	  -new -x509 -days $(EXPIRATION_DAYS) -sha256 \
	  -extensions v3_ca \
	  -key root_ca/private/ca_key.pem \
	  -passin file:root_ca/private/ca_root_phrase \
	  -subj "/C=US/ST=California/L=Menlo Park/O=ONF/OU=Testing Only/CN=VOLTHA Test Root CA" \
	  -out voltha-CA.pem

# server cert creation

voltha.key:
	@echo "## Creating server private key: voltha.key"
	openssl genrsa -out voltha.key $(KEY_SIZE)

voltha.csr: voltha.cnf voltha.key
	@echo "## Creating signing request voltha.csr from voltha.key"
	openssl req -config voltha.cnf \
	  -new -sha256 -key voltha.key \
	  -subj "/C=US/ST=California/L=Menlo Park/O=ONF/OU=Testing Only/CN=VOLTHA Server" \
	  -out voltha.csr

voltha.crt: voltha-CA.pem voltha.cnf voltha.key voltha.csr
	@echo "## Signing voltha.csr to create signed public key: voltha.crt"
	openssl ca -config voltha.cnf \
	  -batch -days $(EXPIRATION_DAYS) -md sha256 \
	  -passin file:root_ca/private/ca_root_phrase \
	  -extensions server_cert \
	  -in voltha.csr \
	  -out voltha.crt

