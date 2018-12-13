THIS_MAKEFILE      := $(abspath $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)))
WORKING_DIR        := $(dir $(THIS_MAKEFILE) )
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

PROFILING=--profile-svg
DOT := $(shell command -v dot 2> /dev/null)
ifndef DOT
$(warning "dot is not available please install graphviz")
PROFILING=
endif

RUN_PYTEST=$(IN_VENV) PYTHONPATH=$(PYTHONPATH) py.test -vvlx $(PROFILING) --cov=$(WORKING_DIR) --cov-report term-missing --cov-report html

.PHONY: test
test: requirements
	@$(IN_VENV) command -v py.test > /dev/null 2>&1 || `echo >&2 "'make requirements' first. Aborting."; exit 1;`
	@rm -rf $(TESTDIR)/__pycache__
	@cd $(WORKING_DIR) && $(RUN_PYTEST) $(TESTDIR)

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

.PHONY: requirements
requirements: create-venv $(OPENOLT_PB2) $(VOLTHA_PB2)
	@$(IN_VENV) pip install --upgrade -r $(WORKING_DIR)test_requirements.txt
	@ virtualenv --relocatable ${VENVDIR}

