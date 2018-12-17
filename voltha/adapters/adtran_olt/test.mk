THIS_MAKEFILE      := $(abspath $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)))
WORKING_DIR        := $(dir $(THIS_MAKEFILE) )
ADAPTER_NAME       := $(notdir $(patsubst %/,%,$(WORKING_DIR)))
ADAPTERS_DIR       := $(dir $(patsubst %/,%,$(WORKING_DIR)))
VOLTHA_DIR         := $(dir $(patsubst %/,%,$(ADAPTERS_DIR)))
PROJ_DIR           := $(VOLTHA_DIR)../

OPENOLT_DIR        := $(ADAPTERS_DIR)openolt
OPENOLT_PROTO      := $(wildcard $(OPENOLT_DIR)/protos/*.proto)
OPENOLT_PB2        := $(patsubst %.proto,%_pb2.py,$(OPENOLT_PROTO))

VOLTHA_PROTO      := $(wildcard $(VOLTHA_DIR)protos/*.proto)
VOLTHA_PB2        := $(patsubst %.proto,%_pb2.py,$(VOLTHA_PROTO))

VENVDIR=$(PROJ_DIR)venv-$(shell uname -s | tr '[:upper:]' '[:lower:]')
TESTDIR=$(WORKING_DIR)test
PYTHONPATH := $(PYTHONPATH):$(VOLTHA_DIR)protos/third_party;
IN_VENV=. '$(VENVDIR)/bin/activate';
TEST_REQ_INSTALLED := $(VENVDIR)/.$(ADAPTER_NAME)-test

PROFILING=--profile-svg
DOT := $(shell command -v dot 2> /dev/null)
ifndef DOT
$(warning "dot is not available please install graphviz")
PROFILING=
endif

RUN_PYTEST=$(IN_VENV) PYTHONPATH=$(PYTHONPATH) py.test -vvlx $(PROFILING)

.PHONY: test
test: requirements
	@rm -rf $(TESTDIR)/__pycache__
	@cd $(WORKING_DIR) && $(RUN_PYTEST) $(TESTDIR)

.PHONY: clean
clean:
	@-rm -rf .coverage
	@-rm -rf htmlcov
	@-rm -rf coverage.xml
	@-rm -rf .pytest_cache
	@-find $(WORKING_DIR) -type f -name '*.pyc' -delete

.PHONY: lint
lint: requirements
	@-$(IN_VENV) pylint `pwd`

.PHONY: create-venv
create-venv: $(VENVDIR)/.built


$(VENVDIR)/.built:
	cd $(PROJ_DIR); make venv

$(OPENOLT_PB2): %_pb2.py : %.proto
	@echo !-- Making $(@) because $< changed ---
	@cd $(OPENOLT_DIR); $(MAKE)

$(VOLTHA_PB2): %_pb2.py : %.proto
	@echo !-- Making $(@) because $< changed ---
	@cd $(VOLTHA_DIR)/protos; $(MAKE) third_party build

$(TEST_REQ_INSTALLED): $(WORKING_DIR)test_requirements.txt \
                       $(PROJ_DIR)requirements.txt
	@$(IN_VENV) pip install --upgrade -r $(WORKING_DIR)test_requirements.txt
	@ python -m virtualenv -p python2 --relocatable ${VENVDIR}
	uname -s > ${@};

.PHONY: requirements
requirements: create-venv $(OPENOLT_PB2) $(VOLTHA_PB2) $(TEST_REQ_INSTALLED)
