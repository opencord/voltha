PROTO_FILES := $(wildcard *.proto) $(wildcard third_party/google/api/*proto)
PROTO_PB2_FILES := $(foreach f,$(PROTO_FILES),$(subst .proto,_pb2.py,$(f)))
PROTO_DESC_FILES := $(foreach f,$(PROTO_FILES),$(subst .proto,.desc,$(f)))

PROTOC_PREFIX := /usr/local
PROTOC_LIBDIR := $(PROTOC_PREFIX)/lib

PROTOC := $(PROTOC_PREFIX)/bin/protoc

PROTOC_VERSION := "3.0.2"
PROTOC_DOWNLOAD_PREFIX := "https://github.com/google/protobuf/releases/download"
PROTOC_DIR := protobuf-$(PROTOC_VERSION)
PROTOC_TARBALL := protobuf-python-$(PROTOC_VERSION).tar.gz
PROTOC_DOWNLOAD_URI := $(PROTOC_DOWNLOAD_PREFIX)/v$(PROTOC_VERSION)/$(PROTOC_TARBALL)
PROTOC_BUILD_TMP_DIR := "/tmp/protobuf-build-$(shell uname -s | tr '[:upper:]' '[:lower:]')"

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